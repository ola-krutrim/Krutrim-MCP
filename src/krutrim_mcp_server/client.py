"""Krutrim Cloud SDK session management and bearer-token refresh."""

from __future__ import annotations

import hashlib
import math
import threading
import time
from typing import Any

import httpx
from krutrim_client import KrutrimClient

from krutrim_mcp_server.compat import patch_client_compatibility as _patch_client_compatibility
from krutrim_mcp_server.config import ACCESS_TOKEN_WITHOUT_REFRESH_TOKEN, Settings
from krutrim_mcp_server.token_validation import (
    decode_unverified_jwt_payload,
    validate_local_access_token,
    validate_local_token_pair,
)


class AuthError(RuntimeError):
    """Raised when the configured access token cannot be resolved."""


ACCESS_TOKEN_PAIR_REQUIRED = (
    "Krutrim Cloud authentication requires KRUTRIM_ACCESS_TOKEN together with "
    "KRUTRIM_REFRESH_TOKEN. API-key authentication is disabled in this release."
)
_REFRESH_WINDOW_SECONDS = 60.0
_REFRESH_PATH = "/iam/v1/token/refresh"


def _credential_context(
    credential: str | None,
    *,
    credential_kind: str,
) -> dict[str, Any]:
    if not credential:
        return {
            "available": False,
            "token_type": "missing",
            "token_fingerprint": None,
            "credential_kind": credential_kind,
        }

    token = credential.strip()
    payload = decode_unverified_jwt_payload(token)
    context: dict[str, Any] = {
        "available": True,
        "token_type": "jwt" if payload is not None else "opaque",
        "token_fingerprint": hashlib.sha256(token.encode("utf-8")).hexdigest()[:12],
        "credential_kind": credential_kind,
        "claims_verified": False,
    }
    if payload is None:
        return context

    for source, target in (
        ("accountId", "account_id"),
        ("account_id", "account_id"),
        ("iss", "account_id"),
        ("uuid", "principal_id"),
        ("customerId", "customer_id"),
        ("customer_id", "customer_id"),
        ("scope", "scope"),
        ("exp", "expires_at_epoch"),
    ):
        value = payload.get(source)
        if value is not None and target not in context:
            context[target] = value
    root_claims = [payload[key] for key in ("isRoot", "is_root") if key in payload]
    if root_claims:
        context["is_root"] = (
            root_claims[0]
            if all(
                isinstance(value, bool) and value is root_claims[0]
                for value in root_claims
            )
            else None
        )
    return context


def _access_token_rejection_reason(access_token: str | None) -> str | None:
    if not access_token:
        return ACCESS_TOKEN_PAIR_REQUIRED
    try:
        validate_local_access_token(
            access_token,
            allow_expired=False,
            now=time.time(),
        )
    except ValueError as exc:
        return str(exc)
    return None


class KrutrimCloudSession:
    """Initialize a KrutrimClient with the configured access token."""

    def __init__(self, settings: Settings) -> None:
        settings.validate()
        self.settings = settings
        self._lock = threading.RLock()
        self._client: KrutrimClient | None = None
        self._credential_context: dict[str, Any] | None = None
        self._access_token = (
            settings.access_token.strip() if settings.access_token else None
        )
        self._refresh_token = (
            settings.refresh_token.strip() if settings.refresh_token else None
        )

    def get_client(self) -> KrutrimClient:
        with self._lock:
            self._ensure_client()
            assert self._client is not None
            return self._client

    def _ensure_client(self) -> None:
        access_token = self._resolve_credential()
        if self._client is None:
            self._client = self._build_client(access_token)
        elif self._client.api_key != access_token:
            self._client.api_key = access_token

    def _resolve_credential(self) -> str:
        if self.settings.credential_kind in {"api_key", "exchanged_access_token"}:
            assert self.settings.api_key is not None
            return self.settings.api_key.strip()
        if self.settings.credential_kind == "access_token":
            assert self._access_token is not None
            assert self._refresh_token is not None
            try:
                validate_local_token_pair(
                    self._access_token,
                    self._refresh_token,
                    allow_expired_access=True,
                    now=time.time(),
                )
            except ValueError as exc:
                raise AuthError(str(exc)) from exc
            if self._access_token_needs_refresh():
                self._refresh_access_token()
            rejection_reason = _access_token_rejection_reason(self._access_token)
            if rejection_reason is not None:
                raise AuthError(rejection_reason)
            assert self._access_token is not None
            return self._access_token
        raise AuthError(ACCESS_TOKEN_PAIR_REQUIRED)

    def _access_token_needs_refresh(self) -> bool:
        return self._token_needs_refresh(self._access_token)

    @staticmethod
    def _token_needs_refresh(access_token: str | None) -> bool:
        context = _credential_context(
            access_token,
            credential_kind="access_token",
        )
        expires_at = context.get("expires_at_epoch")
        if not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool):
            return True
        if isinstance(expires_at, float) and not math.isfinite(expires_at):
            return True
        return expires_at <= time.time() + _REFRESH_WINDOW_SECONDS

    def _refresh_access_token(self) -> None:
        if not self._refresh_token:
            raise AuthError(ACCESS_TOKEN_WITHOUT_REFRESH_TOKEN)
        assert self._access_token is not None
        try:
            validate_local_token_pair(
                self._access_token,
                self._refresh_token,
                allow_expired_access=True,
                now=time.time(),
            )
        except ValueError as exc:
            raise AuthError(str(exc)) from exc
        url = f"{self.settings.base_url}{_REFRESH_PATH}"
        try:
            response = httpx.post(
                url,
                files={
                    "refresh_token": (None, self._refresh_token),
                    "grant_type": (None, "refresh_token"),
                },
                timeout=self.settings.client_timeout_seconds,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise AuthError(
                "Krutrim IAM token refresh is temporarily unavailable. Try again shortly."
            ) from exc

        if response.status_code != 200:
            if response.status_code in {400, 401, 403}:
                raise AuthError(
                    "Krutrim IAM rejected the refresh token. Sign in again and replace "
                    "KRUTRIM_ACCESS_TOKEN and KRUTRIM_REFRESH_TOKEN."
                )
            raise AuthError(
                f"Krutrim IAM token refresh failed with HTTP {response.status_code}. "
                "Try again shortly."
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise AuthError("Krutrim IAM returned an invalid token refresh response.") from exc
        if not isinstance(payload, dict):
            raise AuthError("Krutrim IAM returned an invalid token refresh response.")

        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token.strip():
            raise AuthError("Krutrim IAM token refresh response omitted access_token.")
        access_token = access_token.strip()
        token_type = payload.get("token_type")
        if token_type is not None and (
            not isinstance(token_type, str) or token_type.casefold() != "bearer"
        ):
            raise AuthError("Krutrim IAM returned an unsupported refreshed token type.")

        refresh_token = payload.get("refresh_token")
        if refresh_token is not None and (
            not isinstance(refresh_token, str) or not refresh_token.strip()
        ):
            raise AuthError("Krutrim IAM returned an invalid rotated refresh token.")
        next_refresh_token = (
            refresh_token.strip() if isinstance(refresh_token, str) else self._refresh_token
        )
        assert next_refresh_token is not None
        try:
            validate_local_token_pair(
                access_token,
                next_refresh_token,
                allow_expired_access=False,
                now=time.time(),
            )
        except ValueError as exc:
            raise AuthError("Krutrim IAM returned an invalid refreshed token pair.") from exc

        self._access_token = access_token
        self._refresh_token = next_refresh_token
        if self._client is not None:
            self._client.api_key = access_token

    def _build_client(self, access_token: str) -> KrutrimClient:
        # Disable retries for non-idempotent creates to prevent timeout duplicates.
        kwargs: dict[str, Any] = {
            # krutrim-client 0.5.x names its bearer constructor argument
            # ``api_key`` even when the supplied credential is an IAM access token.
            "api_key": access_token,
            "max_retries": self.settings.client_max_retries,
            "timeout": self.settings.client_timeout_seconds,
        }
        if self.settings.base_url:
            kwargs["base_url"] = self.settings.base_url
        client = KrutrimClient(**kwargs)
        _patch_client_compatibility(client)
        self._credential_context = _credential_context(
            access_token,
            credential_kind="access_token",
        )
        return client

    def health(self) -> dict[str, Any]:
        """Return non-secret local health without making a network request."""
        with self._lock:
            current_credential = (
                self.settings.api_key
                if self.settings.credential_kind in {"api_key", "exchanged_access_token"}
                else self._access_token
            )
            credential_ready = self.settings.credential_kind != "missing"
            refresh_required = (
                self.settings.credential_kind == "access_token"
                and self._access_token_needs_refresh()
            )
            credential_context = _credential_context(
                current_credential,
                credential_kind=(
                    "access_token"
                    if self.settings.credential_kind == "exchanged_access_token"
                    else self.settings.credential_kind
                ),
            )
            self._credential_context = credential_context
            return {
                "ok": credential_ready,
                "configuration_ready": credential_ready,
                "base_url": self.settings.base_url,
                "default_region": self.settings.default_region,
                "read_only": self.settings.read_only,
                "auth_mode": self.settings.credential_kind,
                "refresh_token_configured": bool(self._refresh_token),
                "access_token_refresh_required": refresh_required,
                "authentication_verified": False,
                "client_initialized": self._client is not None,
                "credential_context": credential_context,
            }

    def credential_identity(self) -> dict[str, str]:
        """Return account/customer identity claims carried by the credential."""
        with self._lock:
            context = self._credential_context
            if context is None:
                current_credential = (
                    self.settings.api_key
                    if self.settings.credential_kind
                    in {"api_key", "exchanged_access_token"}
                    else self._access_token
                )
                context = _credential_context(
                    current_credential,
                    credential_kind=(
                        "access_token"
                        if self.settings.credential_kind == "exchanged_access_token"
                        else self.settings.credential_kind
                    ),
                )
                self._credential_context = context

        identity: dict[str, str] = {}
        account_id = context.get("account_id")
        if isinstance(account_id, (str, int)) and not isinstance(account_id, bool):
            identity["account_id"] = str(account_id)
        # IAM issues resource KRNs under the principal when no customer claim exists.
        for key in ("customer_id", "principal_id"):
            value = context.get(key)
            if isinstance(value, str) and value.strip():
                identity["customer_id"] = value.strip()
                break
        return identity

    def is_ready(self) -> bool:
        """Return local configuration readiness without a network request."""
        with self._lock:
            return self.settings.credential_kind != "missing"

    def ensure_ready(self) -> None:
        """Raise a sanitized authentication error unless credentials are ready."""
        with self._lock:
            self._resolve_credential()


_session: KrutrimCloudSession | None = None


def init_session(settings: Settings | None = None) -> KrutrimCloudSession:
    global _session
    _session = KrutrimCloudSession(settings or Settings.from_env())
    return _session


def get_session() -> KrutrimCloudSession:
    if _session is None:
        return init_session()
    return _session
