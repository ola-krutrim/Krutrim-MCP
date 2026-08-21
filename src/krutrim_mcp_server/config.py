"""Environment configuration for the Krutrim MCP server."""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass, field
from urllib.parse import urlparse

from krutrim_mcp_server.token_validation import validate_local_token_pair

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
# API-key authentication is disabled for this stdio release.
_LOCAL_API_KEY_AUTHENTICATION_ENABLED = False
API_KEY_AUTHENTICATION_REMOVED = (
    "Authentication configuration error: API-key authentication is disabled in "
    "this release. Remove KRUTRIM_API_KEY and its legacy aliases, then configure "
    "both KRUTRIM_ACCESS_TOKEN and KRUTRIM_REFRESH_TOKEN."
)
ACCESS_TOKEN_WITHOUT_REFRESH_TOKEN = (
    "Authentication configuration error: KRUTRIM_ACCESS_TOKEN is set, but "
    "KRUTRIM_REFRESH_TOKEN is missing. Add KRUTRIM_REFRESH_TOKEN to the same MCP "
    "server environment. Both values are required for local stdio authentication."
)
REFRESH_TOKEN_WITHOUT_ACCESS_TOKEN = (
    "Authentication configuration error: KRUTRIM_REFRESH_TOKEN is set, but "
    "KRUTRIM_ACCESS_TOKEN is missing. Add KRUTRIM_ACCESS_TOKEN to the same MCP "
    "server environment, or remove the unused KRUTRIM_REFRESH_TOKEN."
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
    if value <= 0:
        raise ValueError(f"{name} must be greater than 0")
    return value


def _validate_http_url(value: str, name: str, *, allow_loopback_http: bool = False) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{name} must be an absolute HTTP(S) URL")
    if parsed.scheme != "https" and not (
        allow_loopback_http and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        raise ValueError(f"{name} must use HTTPS outside loopback development")


def resolve_api_key() -> str | None:
    """Resolve an API key from SDK-compatible environment variable names."""
    configured: list[tuple[str, str]] = []
    for name in _API_KEY_ENV_NAMES:
        value = os.environ.get(name)
        if value and value.strip():
            configured.append((name, value.strip()))
    if not configured:
        return None
    if len({value for _, value in configured}) > 1:
        names = ", ".join(name for name, _ in configured)
        raise ValueError(f"Conflicting API key values are configured in: {names}")
    return configured[0][1]


def _resolve_secret(name: str) -> str | None:
    value = os.environ.get(name)
    if value and value.strip():
        return value.strip()
    return None


def _configured_nonempty_env_names(names: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        name
        for name in names
        if (value := os.environ.get(name)) is not None and bool(value.strip())
    )


def resolve_access_token() -> str | None:
    """Resolve the short-lived IAM bearer access token."""
    return _resolve_secret("KRUTRIM_ACCESS_TOKEN")


def resolve_refresh_token() -> str | None:
    """Resolve the refresh token paired with ``KRUTRIM_ACCESS_TOKEN``."""
    return _resolve_secret("KRUTRIM_REFRESH_TOKEN")


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
    enable_sensitive_tools: bool = False
    access_token: str | None = field(default=None, repr=False)
    refresh_token: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> Settings:
        configured_api_keys = _configured_nonempty_env_names(_API_KEY_ENV_NAMES)
        if configured_api_keys and not _LOCAL_API_KEY_AUTHENTICATION_ENABLED:
            raise ValueError(API_KEY_AUTHENTICATION_REMOVED)
        if "KRUTRIM_MCP_PROFILE" in os.environ:
            warnings.warn(
                "KRUTRIM_MCP_PROFILE is deprecated and ignored; all supported "
                "non-secret tools are registered. Set KRUTRIM_MCP_READ_ONLY=true "
                "to block mutations.",
                RuntimeWarning,
                stacklevel=2,
            )
        settings = cls(
            api_key=resolve_api_key(),
            base_url=os.environ.get("KRUTRIM_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            default_region=os.environ.get("KRUTRIM_DEFAULT_REGION", "").strip(),
            read_only=_env_bool("KRUTRIM_MCP_READ_ONLY", False),
            log_level=os.environ.get("KRUTRIM_MCP_LOG_LEVEL", "INFO").upper(),
            client_max_retries=_env_int("KRUTRIM_CLIENT_MAX_RETRIES", 0),
            client_timeout_seconds=_env_float("KRUTRIM_CLIENT_TIMEOUT_SECONDS", 30.0),
            access_token=resolve_access_token(),
            refresh_token=resolve_refresh_token(),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        has_api_key = bool(self.api_key and self.api_key.strip())
        has_access_token = bool(self.access_token and self.access_token.strip())
        has_refresh_token = bool(self.refresh_token and self.refresh_token.strip())

        if has_api_key and not _LOCAL_API_KEY_AUTHENTICATION_ENABLED:
            raise ValueError(API_KEY_AUTHENTICATION_REMOVED)
        if has_api_key and (has_access_token or has_refresh_token):
            raise ValueError(
                "Configure either KRUTRIM_API_KEY or the KRUTRIM_ACCESS_TOKEN and "
                "KRUTRIM_REFRESH_TOKEN pair, not both"
            )
        if has_access_token and not has_refresh_token:
            raise ValueError(ACCESS_TOKEN_WITHOUT_REFRESH_TOKEN)
        if has_refresh_token and not has_access_token:
            raise ValueError(REFRESH_TOKEN_WITHOUT_ACCESS_TOKEN)
        if has_access_token and has_refresh_token:
            assert self.access_token is not None
            assert self.refresh_token is not None
            validate_local_token_pair(
                self.access_token,
                self.refresh_token,
                allow_expired_access=True,
            )

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
        if self.api_key and self.api_key.strip():
            return "api_key"
        if self.access_token and self.access_token.strip():
            return "access_token"
        return "missing"
