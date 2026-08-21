"""Value-level guards for local stdio IAM token pairs."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from krutrim_mcp_server.client import AuthError, KrutrimCloudSession
from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import main
from tests.auth_tokens import make_iam_token_pair


def _settings(access_token: str, refresh_token: str) -> Settings:
    return Settings(
        api_key=None,
        base_url="https://cloud.olakrutrim.com",
        default_region="",
        read_only=False,
        log_level="ERROR",
        client_max_retries=0,
        access_token=access_token,
        refresh_token=refresh_token,
    )


@pytest.mark.parametrize(
    "access_token",
    (
        "opaque-api-key-value",
        "opaque.part.token",
        "not-a-jwt",
    ),
)
def test_rejects_opaque_api_key_values_in_access_token_before_network(
    access_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod

    _, refresh_token = make_iam_token_pair()
    post = MagicMock(side_effect=AssertionError("invalid values must not reach IAM"))
    sdk = MagicMock(side_effect=AssertionError("invalid values must not reach SDK"))
    monkeypatch.setattr(client_mod.httpx, "post", post)
    monkeypatch.setattr(client_mod, "KrutrimClient", sdk)

    with pytest.raises(ValueError) as stopped:
        KrutrimCloudSession(_settings(access_token, refresh_token))

    message = str(stopped.value)
    assert "API-key" in message
    assert access_token not in message
    assert refresh_token not in message
    post.assert_not_called()
    sdk.assert_not_called()


@pytest.mark.parametrize(
    "scope",
    (
        "programmatic-access",
        "progAccess",
        "service-account",
        "cloud-console programmatic-access",
    ),
)
def test_rejects_programmatic_jwt_values_in_access_token(scope: str) -> None:
    access_token, refresh_token = make_iam_token_pair(
        access_overrides={"scope": scope}
    )

    with pytest.raises(ValueError, match="programmatic-access") as stopped:
        _settings(access_token, refresh_token).validate()

    assert access_token not in str(stopped.value)
    assert refresh_token not in str(stopped.value)


def test_accepts_current_iam_session_shape_without_scope_or_session_status() -> None:
    access_token, refresh_token = make_iam_token_pair(
        access_overrides={"scope": ""},
        access_remove_claims=("sessionStatus",),
    )

    _settings(access_token, refresh_token).validate()


@pytest.mark.parametrize(
    ("claim", "value"),
    (
        ("auth_method", "api_key"),
        ("credential_type", "programmatic-access"),
        ("token_use", "api-key"),
    ),
)
def test_rejects_explicit_api_key_origin_markers(claim: str, value: str) -> None:
    access_token, refresh_token = make_iam_token_pair(
        access_overrides={claim: value}
    )

    with pytest.raises(ValueError, match="API-key"):
        _settings(access_token, refresh_token).validate()


@pytest.mark.parametrize(
    "refresh_value_factory",
    (
        lambda access_token: "opaque-api-key-value",
        lambda access_token: access_token,
    ),
)
def test_rejects_api_key_or_access_token_values_in_refresh_token(
    refresh_value_factory,
) -> None:
    access_token, _ = make_iam_token_pair()
    refresh_token = refresh_value_factory(access_token)

    with pytest.raises(ValueError, match="KRUTRIM_REFRESH_TOKEN") as stopped:
        _settings(access_token, refresh_token).validate()

    assert access_token not in str(stopped.value)
    assert refresh_token not in str(stopped.value)


def test_rejects_tokens_from_different_iam_sessions() -> None:
    access_token, _ = make_iam_token_pair()
    _, refresh_token = make_iam_token_pair(
        refresh_overrides={"sid": "different-session"}
    )

    with pytest.raises(ValueError, match="not from the same IAM session"):
        _settings(access_token, refresh_token).validate()


def test_expired_session_access_token_remains_eligible_for_refresh() -> None:
    access_token, refresh_token = make_iam_token_pair(access_exp=1)

    _settings(access_token, refresh_token).validate()


def test_expired_refresh_token_is_rejected_before_network() -> None:
    access_token, refresh_token = make_iam_token_pair(refresh_exp=1)

    with pytest.raises(ValueError, match="KRUTRIM_REFRESH_TOKEN is expired"):
        _settings(access_token, refresh_token).validate()


def test_doctor_rejects_api_key_value_without_exposing_it(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, refresh_token = make_iam_token_pair()
    api_key_value = "opaque-api-key-value"
    for name in (
        "KRUTRIM_API_KEY",
        "KRUTRIM_CLIENT_API_KEY",
        "krutrim_client_API_KEY",
        "KRUTRIMCLIENT_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", api_key_value)
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", refresh_token)

    with pytest.raises(SystemExit) as stopped:
        main(["--doctor"])

    output = capsys.readouterr()
    rendered = f"{stopped.value}\n{output.out}\n{output.err}"
    assert "API-key" in rendered
    assert api_key_value not in rendered
    assert refresh_token not in rendered


def test_rejects_programmatic_access_token_returned_by_refresh_before_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod

    old_access_token, refresh_token = make_iam_token_pair(access_exp=1)
    programmatic_token, _ = make_iam_token_pair(
        access_overrides={"scope": "programmatic-access"}
    )
    response = MagicMock(status_code=200)
    response.json.return_value = {"access_token": programmatic_token}
    post = MagicMock(return_value=response)
    sdk = MagicMock(side_effect=AssertionError("invalid refresh must not reach SDK"))
    monkeypatch.setattr(client_mod.httpx, "post", post)
    monkeypatch.setattr(client_mod, "KrutrimClient", sdk)
    session = KrutrimCloudSession(_settings(old_access_token, refresh_token))

    with pytest.raises(AuthError, match="invalid refreshed token pair"):
        session.get_client()

    post.assert_called_once()
    sdk.assert_not_called()
