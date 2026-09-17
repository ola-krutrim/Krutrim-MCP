"""Lazy Krutrim Cloud SDK sessions using direct opaque API keys."""

from __future__ import annotations

import threading
from typing import Any

from krutrim_client import KrutrimClient

from krutrim_mcp_server import logging_utils
from krutrim_mcp_server.compat import patch_client_compatibility as _patch_client_compatibility
from krutrim_mcp_server.config import Settings


class AuthError(RuntimeError):
    """Raised when the required API key is missing."""


API_KEY_REQUIRED = "Krutrim Cloud authentication requires KRUTRIM_API_KEY."


class KrutrimCloudSession:
    """Initialize one SDK client lazily; Cloud validates the key downstream."""

    def __init__(self, settings: Settings) -> None:
        settings.validate()
        self.settings = settings
        self._lock = threading.RLock()
        self._client: KrutrimClient | None = None

    def get_client(self) -> KrutrimClient:
        with self._lock:
            self.ensure_ready()
            if self._client is None:
                assert self.settings.api_key is not None
                self._client = self._build_client(self.settings.api_key)
            return self._client

    def _build_client(self, api_key: str) -> KrutrimClient:
        # No retries: mutation APIs do not provide idempotency guarantees.
        kwargs: dict[str, Any] = {
            "api_key": api_key,
            "max_retries": self.settings.client_max_retries,
            "timeout": self.settings.client_timeout_seconds,
        }
        if self.settings.base_url:
            kwargs["base_url"] = self.settings.base_url
        client = KrutrimClient(**kwargs)
        _patch_client_compatibility(client)
        return client

    def health(self) -> dict[str, Any]:
        """Return non-secret local readiness without making a network request."""
        with self._lock:
            ready = self.is_ready()
            return {
                "ok": ready,
                "configuration_ready": ready,
                "base_url": self.settings.base_url,
                "default_region": self.settings.default_region,
                "read_only": self.settings.read_only,
                "auth_mode": self.settings.credential_kind,
                "authentication_verified": False,
                "client_initialized": self._client is not None,
            }

    def is_ready(self) -> bool:
        """Local configuration readiness is not downstream authentication."""
        return self.settings.api_key is not None

    def ensure_ready(self) -> None:
        """Require an API key without initializing the SDK or doing network I/O."""
        if not self.is_ready():
            raise AuthError(API_KEY_REQUIRED)


_session: KrutrimCloudSession | None = None


def init_session(settings: Settings | None = None) -> KrutrimCloudSession:
    global _session
    settings = settings or Settings.from_env()
    session = KrutrimCloudSession(settings)
    logging_utils.set_redaction_secrets((settings.api_key,) if settings.api_key else ())
    _session = session
    return _session


def get_session() -> KrutrimCloudSession:
    if _session is None:
        return init_session()
    return _session
