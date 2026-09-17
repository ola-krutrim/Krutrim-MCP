"""Environment configuration for the Krutrim MCP server."""

from __future__ import annotations

import math
import os
import warnings
from dataclasses import dataclass, field
from urllib.parse import urlparse

DEFAULT_BASE_URL = "https://cloud.olakrutrim.com"
KNOWN_REGIONS = ("In-Bangalore-1", "In-Hyderabad-1")
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}
_API_KEY_ENV_NAMES = (
    "KRUTRIM_API_KEY",
    "KRUTRIM_CLIENT_API_KEY",
    "krutrim_client_API_KEY",
    "KRUTRIMCLIENT_API_KEY",
)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(
        f"{name} must be one of: {', '.join(sorted(_TRUE_VALUES | _FALSE_VALUES))}"
    )


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 0:
        raise ValueError(f"{name} must be greater than or equal to 0")
    return value


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and greater than 0")
    return value


def _validate_http_url(value: str, name: str, *, allow_loopback_http: bool = False) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{name} must be an absolute HTTP(S) URL")
    if parsed.scheme != "https" and not (
        allow_loopback_http and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        raise ValueError(f"{name} must use HTTPS outside loopback development")


def _validate_api_key(value: str) -> None:
    """Reject unsafe header values and token-shaped credentials, without decoding."""
    if (
        not isinstance(value, str)
        or not value
        or any(not 33 <= ord(char) <= 126 for char in value)
        or value.lower() == "bearer"
        or value.lower().startswith("bearer:")
        or value.count(".") >= 2
    ):
        raise ValueError(
            "Authentication configuration error: KRUTRIM_API_KEY must be a raw "
            "opaque API key, without whitespace, control/non-ASCII characters, "
            "a Bearer prefix, or JWT dot-separated tokens."
        )


def resolve_api_key() -> str | None:
    """Resolve an API key from SDK-compatible environment variable names."""
    configured: list[tuple[str, str]] = []
    for name in _API_KEY_ENV_NAMES:
        value = os.environ.get(name)
        if value:
            _validate_api_key(value)
            configured.append((name, value))
    if not configured:
        return None
    if len({value for _, value in configured}) > 1:
        names = ", ".join(name for name, _ in configured)
        raise ValueError(f"Conflicting API key values are configured in: {names}")
    return configured[0][1]


@dataclass(frozen=True)
class Settings:
    api_key: str | None = field(repr=False)
    base_url: str
    default_region: str
    read_only: bool
    log_level: str
    client_max_retries: int
    tool_profile: str | None = None
    client_timeout_seconds: float = 30.0
    create_timeout_seconds: float = 600.0
    enable_sensitive_tools: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        api_key = resolve_api_key()
        # Inherited tokens must not block an explicitly configured API key.
        # They are never used as credentials or as a fallback.
        legacy_names = ("KRUTRIM_ACCESS_TOKEN", "KRUTRIM_REFRESH_TOKEN")
        if api_key is None and any(os.environ.get(name) for name in legacy_names):
            raise ValueError(
                "Authentication configuration error: Set KRUTRIM_API_KEY "
                "to your Krutrim Cloud API key."
            )
        if "KRUTRIM_MCP_PROFILE" in os.environ:
            warnings.warn(
                "KRUTRIM_MCP_PROFILE is deprecated and ignored; all supported "
                "non-secret tools are registered. Set KRUTRIM_MCP_READ_ONLY=true "
                "to block mutations.",
                RuntimeWarning,
                stacklevel=2,
            )
        settings = cls(
            api_key=api_key,
            base_url=os.environ.get("KRUTRIM_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            default_region=os.environ.get("KRUTRIM_DEFAULT_REGION", "").strip(),
            read_only=_env_bool("KRUTRIM_MCP_READ_ONLY", False),
            log_level=os.environ.get("KRUTRIM_MCP_LOG_LEVEL", "INFO").upper(),
            client_max_retries=_env_int("KRUTRIM_CLIENT_MAX_RETRIES", 0),
            client_timeout_seconds=_env_float("KRUTRIM_CLIENT_TIMEOUT_SECONDS", 30.0),
            create_timeout_seconds=_env_float("KRUTRIM_CREATE_TIMEOUT_SECONDS", 600.0),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.api_key is not None:
            _validate_api_key(self.api_key)
        for name, value in (
            ("KRUTRIM_CLIENT_TIMEOUT_SECONDS", self.client_timeout_seconds),
            ("KRUTRIM_CREATE_TIMEOUT_SECONDS", self.create_timeout_seconds),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and greater than 0")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("KRUTRIM_MCP_LOG_LEVEL is invalid")
        if self.client_max_retries != 0:
            raise ValueError(
                "KRUTRIM_CLIENT_MAX_RETRIES must remain 0 until mutation APIs support "
                "idempotency keys"
            )

        _validate_http_url(self.base_url, "KRUTRIM_BASE_URL", allow_loopback_http=True)

    @property
    def credential_kind(self) -> str:
        """Return the configured credential path without inspecting token contents."""
        if self.api_key:
            return "api_key"
        return "missing"
