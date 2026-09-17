"""Offline contracts for direct opaque API-key authentication."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any

import httpx
import pytest
from krutrim_client import KrutrimClient

from krutrim_mcp_server import client as client_mod
from krutrim_mcp_server.client import KrutrimCloudSession
from krutrim_mcp_server.config import Settings

API_KEY = "test-api-key-for-offline-tests"
LEGACY_ENV_NAMES = ("KRUTRIM_ACCESS_TOKEN", "KRUTRIM_REFRESH_TOKEN")
API_KEY_ENV_NAMES = (
    "KRUTRIM_API_KEY",
    "KRUTRIM_CLIENT_API_KEY",
    "krutrim_client_API_KEY",
    "KRUTRIMCLIENT_API_KEY",
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.upper().startswith(("KRUTRIM", "KPOD")):
            monkeypatch.delenv(name)


def test_api_key_reaches_real_sdk_authorization_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KRUTRIM_API_KEY", API_KEY)
    requests: list[httpx.Request] = []
    constructed: list[KrutrimClient] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    def factory(**kwargs: Any) -> KrutrimClient:
        sdk = KrutrimClient(
            **kwargs, http_client=httpx.Client(transport=httpx.MockTransport(respond))
        )
        constructed.append(sdk)
        return sdk

    monkeypatch.setattr(client_mod, "KrutrimClient", factory)
    settings = Settings.from_env()
    session = KrutrimCloudSession(settings)
    assert constructed == []
    try:
        sdk = session.get_client()
        assert sdk.get("/offline-auth-contract", cast_to=httpx.Response).json() == {"ok": True}
        assert session.get_client() is sdk
        assert len(constructed) == 1
        assert sdk.max_retries == 0
        assert sdk.timeout == 30.0
        assert len(requests) == 1
        assert str(requests[0].url) == settings.base_url + "/offline-auth-contract"
        assert requests[0].headers["authorization"] == f"Bearer {API_KEY}"
        assert settings.api_key == API_KEY
    finally:
        for sdk in constructed:
            sdk.close()


@pytest.mark.parametrize("name", LEGACY_ENV_NAMES)
@pytest.mark.parametrize("key_present", [False, True])
@pytest.mark.parametrize("legacy_value", ["obsolete-secret", "   "])
def test_legacy_credentials_ignored_only_with_api_key(
    monkeypatch: pytest.MonkeyPatch, name: str, key_present: bool, legacy_value: str,
) -> None:
    monkeypatch.setenv(name, legacy_value)
    if key_present:
        monkeypatch.setenv("KRUTRIM_API_KEY", API_KEY)
        settings = Settings.from_env()
        assert settings.api_key == API_KEY
        assert KrutrimCloudSession(settings).is_ready()
        assert os.environ[name] == legacy_value
        return
    with pytest.raises(ValueError) as stopped:
        Settings.from_env()
    message = str(stopped.value)
    assert message == (
        "Authentication configuration error: Set KRUTRIM_API_KEY "
        "to your Krutrim Cloud API key."
    )
    assert "obsolete-secret" not in message
    assert API_KEY not in message


MALFORMED_KEYS = [
    " leading", "trailing ", "inner space", "tab\tkey", "line\nkey", "cr\rkey",
    "null\x00key", "delete\x7fkey", "control\x1fkey", "non-ascii-é", "   ",
    "Bearer test-key", "bearer:test-key", "opaque.part.token", "a..b", "a.b.c.d.e",
]


@pytest.mark.parametrize("source,key", [
    (source, key)
    for source in ("direct", *API_KEY_ENV_NAMES)
    for key in MALFORMED_KEYS
    if source == "direct" or "\x00" not in key
])
def test_malformed_keys_are_rejected_without_normalizing_or_echoing(
    monkeypatch: pytest.MonkeyPatch, key: str, source: str,
) -> None:
    with pytest.raises(ValueError, match="KRUTRIM_API_KEY") as stopped:
        if source == "direct":
            settings = Settings.from_env()
            KrutrimCloudSession(replace(settings, api_key=key))
        else:
            monkeypatch.setenv(source, key)
            Settings.from_env()
    assert key not in str(stopped.value)


@pytest.mark.parametrize("name", API_KEY_ENV_NAMES)
@pytest.mark.parametrize(
    "key", [API_KEY, "x", "a" * 10000, "opaque.key", "opaque_+/=-~"],
    ids=["synthetic", "short", "long", "single-dot", "header-safe-symbols"],
)
def test_aliases_preserve_opaque_keys_without_invented_length_limits(
    monkeypatch: pytest.MonkeyPatch, name: str, key: str,
) -> None:
    monkeypatch.setenv(name, key)
    assert Settings.from_env().api_key == key


@pytest.mark.parametrize("name", API_KEY_ENV_NAMES[1:])
def test_aliases_agree_or_reject_conflicting_values(
    monkeypatch: pytest.MonkeyPatch, name: str,
) -> None:
    monkeypatch.setenv("KRUTRIM_API_KEY", API_KEY)
    monkeypatch.setenv(name, API_KEY)
    assert Settings.from_env().api_key == API_KEY
    monkeypatch.setenv(name, "conflicting-offline-key")
    with pytest.raises(ValueError, match="Conflicting") as stopped:
        Settings.from_env()
    assert API_KEY not in str(stopped.value)
    assert "conflicting-offline-key" not in str(stopped.value)


@pytest.mark.parametrize("key", [None, API_KEY])
def test_readiness_is_local_and_health_contains_no_credential_metadata(
    monkeypatch: pytest.MonkeyPatch, key: str | None,
) -> None:
    if key:
        monkeypatch.setenv("KRUTRIM_API_KEY", key)
    settings = Settings.from_env()
    assert not hasattr(settings, "access_token")
    assert not hasattr(settings, "refresh_token")
    session = KrutrimCloudSession(settings)
    assert not hasattr(session, "credential_identity")
    assert session.health() == {
        "ok": bool(key), "configuration_ready": bool(key),
        "base_url": settings.base_url, "default_region": settings.default_region,
        "read_only": settings.read_only, "auth_mode": "api_key" if key else "missing",
        "authentication_verified": False, "client_initialized": False,
    }
    assert session.is_ready() is bool(key)
    if key:
        session.ensure_ready()
        assert session.health()["client_initialized"] is False
    else:
        for action in (session.ensure_ready, session.get_client):
            with pytest.raises(client_mod.AuthError, match="KRUTRIM_API_KEY"):
                action()


def test_401_guidance_names_api_key_only() -> None:
    from krutrim_mcp_server.errors import format_error
    class Unauthorized(Exception):
        status_code = 401
    message = format_error(Unauthorized("sensitive backend text"))
    assert "KRUTRIM_API_KEY" in message
    assert "KRUTRIM_ACCESS_TOKEN" not in message
    assert "KRUTRIM_REFRESH_TOKEN" not in message
    assert "sensitive backend text" not in message


def test_init_session_registers_only_validated_key_and_clears_on_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import logging_utils
    registered: list[tuple[str, ...]] = []
    monkeypatch.setattr(logging_utils, "set_redaction_secrets", registered.append)
    monkeypatch.setattr(client_mod, "_session", None)
    monkeypatch.setenv("KRUTRIM_API_KEY", API_KEY)
    settings = Settings.from_env()
    initialized = client_mod.init_session(settings)
    assert client_mod.get_session() is initialized
    assert registered == [(API_KEY,)]
    with pytest.raises(ValueError):
        client_mod.init_session(replace(settings, api_key="bad key"))
    assert registered == [(API_KEY,)]
    assert client_mod.get_session() is initialized
    client_mod.init_session(replace(settings, api_key=None))
    assert registered == [(API_KEY,), ()]


@pytest.mark.parametrize("status", [401, 403])
def test_real_sdk_denials_make_one_request_without_refresh_or_retry(
    monkeypatch: pytest.MonkeyPatch, status: int,
) -> None:
    from krutrim_client import APIStatusError

    from krutrim_mcp_server.errors import format_error
    monkeypatch.setenv("KRUTRIM_API_KEY", API_KEY)
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(status, json={"message": "denied " + API_KEY})

    def factory(**kwargs):
        return KrutrimClient(
            **kwargs, http_client=httpx.Client(transport=httpx.MockTransport(respond))
        )

    monkeypatch.setattr(client_mod, "KrutrimClient", factory)
    session = KrutrimCloudSession(Settings.from_env())
    sdk = session.get_client()
    try:
        with pytest.raises(APIStatusError) as stopped:
            sdk.get("/offline-auth-contract", cast_to=httpx.Response)
        assert stopped.value.status_code == status
        assert API_KEY not in format_error(stopped.value)
        assert len(requests) == 1
        assert requests[0].url.path == "/offline-auth-contract"
        assert requests[0].headers["authorization"] == f"Bearer {API_KEY}"
        assert session.get_client() is sdk
        assert len(requests) == 1
        assert session.health()["authentication_verified"] is False
    finally:
        sdk.close()


def test_concurrent_callers_share_one_lazy_sdk_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    monkeypatch.setenv("KRUTRIM_API_KEY", API_KEY)
    constructed: list[KrutrimClient] = []

    def factory(**kwargs):
        sdk = KrutrimClient(
            **kwargs, http_client=httpx.Client(transport=httpx.MockTransport(
                lambda _: pytest.fail("client construction must not make requests")
            ))
        )
        constructed.append(sdk)
        return sdk

    monkeypatch.setattr(client_mod, "KrutrimClient", factory)
    session = KrutrimCloudSession(Settings.from_env())
    barrier = Barrier(8)

    def get_client(_):
        barrier.wait(timeout=10)
        return session.get_client()

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            clients = list(pool.map(get_client, range(8)))
        assert len(constructed) == 1
        assert all(client is constructed[0] for client in clients)
        assert session.health()["client_initialized"] is True
    finally:
        for sdk in constructed:
            sdk.close()
