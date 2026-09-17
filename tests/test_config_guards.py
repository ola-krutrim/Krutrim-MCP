"""Unit tests for config and guards."""

from __future__ import annotations

import os

import pytest

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.errors import format_error
from krutrim_mcp_server.guards import GuardError, ensure_confirmed, ensure_writable
from krutrim_mcp_server.logging_utils import redact_text
from krutrim_mcp_server.serialize import to_jsonable


@pytest.fixture(autouse=True)
def _clear_auth_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.upper().startswith(("KRUTRIM", "KPOD")):
            monkeypatch.delenv(name)


def test_settings_repr_hides_api_key() -> None:
    settings = Settings(
        api_key="test-api-key-for-offline-tests",
        base_url="https://cloud.olakrutrim.com",
        default_region="",
        read_only=False,
        log_level="INFO",
        client_max_retries=0,
    )
    assert "test-api-key-for-offline-tests" not in repr(settings)


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
    assert "KRUTRIM_API_KEY" in msg
    assert "KRUTRIM_ACCESS_TOKEN" not in msg
    assert "KRUTRIM_REFRESH_TOKEN" not in msg


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
