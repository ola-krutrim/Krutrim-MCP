"""Unit tests for config and guards."""

from __future__ import annotations

import os

import pytest

from krutrim_mcp_server import config as config_mod
from krutrim_mcp_server.config import (
    Settings,
    resolve_access_token,
    resolve_refresh_token,
)
from krutrim_mcp_server.errors import format_error
from krutrim_mcp_server.guards import GuardError, ensure_confirmed, ensure_writable
from krutrim_mcp_server.logging_utils import redact_text
from krutrim_mcp_server.serialize import to_jsonable
from tests.auth_tokens import TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN

_REMOVED_API_KEY_ENV_NAMES = (
    "KRUTRIM_API_KEY",
    "KRUTRIM_CLIENT_API_KEY",
    "krutrim_client_API_KEY",
    "KRUTRIMCLIENT_API_KEY",
)

@pytest.fixture(autouse=True)
def _clear_auth_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*_REMOVED_API_KEY_ENV_NAMES, "KRUTRIM_ACCESS_TOKEN", "KRUTRIM_REFRESH_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("name", _REMOVED_API_KEY_ENV_NAMES)
def test_api_key_environment_variables_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setenv(name, "legacy-api-key")

    with pytest.raises(ValueError, match="API-key authentication is disabled"):
        Settings.from_env()


@pytest.mark.parametrize(
    "toggle_name",
    (
        "KRUTRIM_MCP_ALLOW_API_KEY_AUTH",
        "LOCAL_API_KEY_AUTHENTICATION_ENABLED",
        "_LOCAL_API_KEY_AUTHENTICATION_ENABLED",
    ),
)
def test_user_environment_cannot_enable_dormant_api_key_authentication(
    monkeypatch: pytest.MonkeyPatch,
    toggle_name: str,
) -> None:
    monkeypatch.setenv(toggle_name, "true")
    monkeypatch.setenv("KRUTRIM_API_KEY", "legacy-api-key")

    with pytest.raises(ValueError, match="API-key authentication is disabled"):
        Settings.from_env()


@pytest.mark.parametrize("name", _REMOVED_API_KEY_ENV_NAMES)
def test_release_policy_gate_preserves_api_key_configuration_path(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setattr(config_mod, "_LOCAL_API_KEY_AUTHENTICATION_ENABLED", True)
    monkeypatch.setenv(name, "future-reviewed-api-key")

    settings = Settings.from_env()

    assert settings.credential_kind == "api_key"
    assert settings.access_token is None
    assert settings.refresh_token is None


def test_release_policy_gate_still_rejects_mixed_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config_mod, "_LOCAL_API_KEY_AUTHENTICATION_ENABLED", True)
    access_token, refresh_token = TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN
    settings = Settings(
        api_key="future-reviewed-api-key",
        base_url="https://cloud.olakrutrim.com",
        default_region="",
        read_only=False,
        log_level="INFO",
        client_max_retries=0,
        access_token=access_token,
        refresh_token=refresh_token,
    )

    with pytest.raises(ValueError, match="not both"):
        settings.validate()


def test_resolves_access_and_refresh_token_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", f" {TEST_ACCESS_TOKEN} ")
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", f" {TEST_REFRESH_TOKEN} ")

    settings = Settings.from_env()

    assert resolve_access_token() == TEST_ACCESS_TOKEN
    assert resolve_refresh_token() == TEST_REFRESH_TOKEN
    assert settings.credential_kind == "access_token"


@pytest.mark.parametrize("name", _REMOVED_API_KEY_ENV_NAMES)
@pytest.mark.parametrize("api_key_value", ["", "   "])
def test_blank_removed_api_key_variable_allows_access_and_refresh_token_pair(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    api_key_value: str,
) -> None:
    monkeypatch.setenv(name, api_key_value)
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", TEST_ACCESS_TOKEN)
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", TEST_REFRESH_TOKEN)

    settings = Settings.from_env()

    assert settings.credential_kind == "access_token"
    assert settings.api_key is None


def test_access_token_requires_refresh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", "access-token")
    monkeypatch.delenv("KRUTRIM_REFRESH_TOKEN", raising=False)

    with pytest.raises(ValueError) as stopped:
        Settings.from_env()

    message = str(stopped.value)
    assert message.startswith("Authentication configuration error:")
    assert "KRUTRIM_ACCESS_TOKEN is set" in message
    assert "KRUTRIM_REFRESH_TOKEN is missing" in message
    assert "Both values are required" in message


def test_refresh_token_requires_access_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", "refresh-token")

    with pytest.raises(ValueError) as stopped:
        Settings.from_env()

    message = str(stopped.value)
    assert "KRUTRIM_REFRESH_TOKEN is set" in message
    assert "KRUTRIM_ACCESS_TOKEN is missing" in message


@pytest.mark.parametrize("name", _REMOVED_API_KEY_ENV_NAMES)
def test_api_key_environment_is_rejected_even_with_bearer_pair(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setenv(name, "legacy-api-key")
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", "access-token")
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", "refresh-token")

    with pytest.raises(ValueError, match="API-key authentication is disabled"):
        Settings.from_env()


@pytest.mark.parametrize(
    ("access_token", "refresh_token"),
    [
        ("access-token", None),
        (None, "refresh-token"),
        ("access-token", "refresh-token"),
    ],
)
def test_direct_settings_reject_api_key_credentials(
    access_token: str | None,
    refresh_token: str | None,
) -> None:
    settings = Settings(
        api_key="api-key",
        base_url="https://cloud.olakrutrim.com",
        default_region="",
        read_only=False,
        log_level="INFO",
        client_max_retries=0,
        access_token=access_token,
        refresh_token=refresh_token,
    )

    with pytest.raises(
        ValueError,
        match="API-key authentication is disabled",
    ):
        settings.validate()


def test_public_oauth_still_rejects_local_credentials_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KRUTRIM_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("KRUTRIM_BASE_URL", "https://cloud.olakrutrim.com")
    monkeypatch.setenv("KRUTRIM_API_KEY", "api-key")
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", "access-token")
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", "refresh-token")

    with pytest.raises(ValueError, match="API-key authentication is disabled"):
        Settings.from_env()


def test_settings_repr_hides_all_credentials() -> None:
    settings = Settings(
        api_key=None,
        base_url="https://cloud.olakrutrim.com",
        default_region="",
        read_only=False,
        log_level="INFO",
        client_max_retries=0,
        access_token="access-token-secret",
        refresh_token="refresh-token-secret",
    )

    rendered = repr(settings)
    assert "access-token-secret" not in rendered
    assert "refresh-token-secret" not in rendered


def test_settings_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRUTRIM_MCP_READ_ONLY", "true")
    monkeypatch.setenv("KRUTRIM_DEFAULT_REGION", "In-Hyderabad-1")
    s = Settings.from_env()
    assert s.read_only is True
    assert s.default_region == "In-Hyderabad-1"


def test_settings_rejects_ambiguous_boolean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRUTRIM_MCP_READ_ONLY", "sometimes")
    with pytest.raises(ValueError, match="must be one of"):
        Settings.from_env()


def test_settings_defaults_to_full_writable_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KRUTRIM_MCP_PROFILE", raising=False)
    monkeypatch.delenv("KRUTRIM_MCP_READ_ONLY", raising=False)
    settings = Settings.from_env()
    assert settings.tool_profile is None
    assert settings.read_only is False


def test_legacy_profile_environment_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KRUTRIM_MCP_PROFILE", "legacy-client-value")

    with pytest.warns(RuntimeWarning, match="deprecated and ignored"):
        settings = Settings.from_env()

    assert settings.tool_profile is None
    assert settings.read_only is False


def test_settings_has_no_code_default_region(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KRUTRIM_DEFAULT_REGION", raising=False)
    s = Settings.from_env()
    assert s.default_region == ""


def test_settings_disables_client_retries_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KRUTRIM_CLIENT_MAX_RETRIES", raising=False)
    s = Settings.from_env()
    assert s.client_max_retries == 0


def test_settings_client_retries_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRUTRIM_CLIENT_MAX_RETRIES", "1")
    with pytest.raises(ValueError, match="must remain 0"):
        Settings.from_env()


def test_settings_does_not_accept_login_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KRUTRIM_EMAIL", "user@example.com")
    monkeypatch.setenv("KRUTRIM_PASSWORD", "not-a-runtime-credential")
    monkeypatch.setenv("KRUTRIM_IS_ROOT_USER", "true")

    settings = Settings.from_env()

    assert settings.api_key is None
    assert not hasattr(settings, "email")
    assert not hasattr(settings, "password")
    assert not hasattr(settings, "is_root_user")


def test_ensure_writable_blocks() -> None:
    s = Settings(
        api_key=None,
        base_url="https://cloud.olakrutrim.com",
        default_region="In-Bangalore-1",
        read_only=True,
        log_level="INFO",
        client_max_retries=0,
    )
    with pytest.raises(GuardError, match="READ_ONLY"):
        ensure_writable(s, "create_vpc")


def test_ensure_confirmed() -> None:
    with pytest.raises(GuardError, match="confirm=true"):
        ensure_confirmed(False, "delete_vpc", "vpc-1")
    ensure_confirmed(True, "delete_vpc", "vpc-1")


def test_format_error_401() -> None:
    class Fake(Exception):
        status_code = 401

    msg = format_error(Fake("nope"))
    assert "401" in msg
    assert "KRUTRIM_ACCESS_TOKEN" in msg
    assert "KRUTRIM_REFRESH_TOKEN" in msg
    assert "KRUTRIM_API_KEY" not in msg


def test_format_error_redacts_secrets() -> None:
    msg = format_error(RuntimeError('request failed: {"secret_key": "value-123"}'))
    assert "value-123" not in msg
    assert "***" in msg


@pytest.mark.parametrize(
    "message, secret",
    [
        ('{"authorization": "Bearer abc.def"}', "abc.def"),
        ("password=two words", "two words"),
        ("client_secret: very-secret", "very-secret"),
    ],
)
def test_log_redaction_consumes_complete_secret_value(message: str, secret: str) -> None:
    assert secret not in redact_text(message)


def test_to_jsonable_pydantic_like() -> None:
    class Model:
        def model_dump(self, mode: str = "python") -> dict:
            return {"a": 1, "b": [2, 3]}

    assert to_jsonable(Model()) == {"a": 1, "b": [2, 3]}
    assert to_jsonable({"x": Model()}) == {"x": {"a": 1, "b": [2, 3]}}


def test_to_jsonable_redacts_common_token_shapes() -> None:
    encoded_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"
    result = to_jsonable(
        {
            "token": "opaque-token",
            "client_secret": "client-value",
            "message": "Authorization failed for Bearer bearer-value",
            "raw": encoded_jwt,
            "embedded": f"request failed for {encoded_jwt}",
        }
    )
    assert result["token"] == "***REDACTED***"
    assert result["client_secret"] == "***REDACTED***"
    assert "bearer-value" not in result["message"]
    assert result["raw"] == "***REDACTED***"
    assert encoded_jwt not in result["embedded"]
    assert encoded_jwt not in redact_text(f"request failed for {encoded_jwt}")


def test_env_example_exists() -> None:
    root = os.path.dirname(os.path.dirname(__file__))
    assert os.path.isfile(os.path.join(root, ".env.example"))
