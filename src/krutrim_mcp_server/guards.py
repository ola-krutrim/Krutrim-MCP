"""Safety guards for mutating MCP tools."""

from __future__ import annotations

from krutrim_mcp_server.config import Settings


class GuardError(ValueError):
    """Raised when a safety guard blocks an operation."""


def ensure_writable(settings: Settings, operation: str) -> None:
    if settings.read_only:
        raise GuardError(
            f"Blocked '{operation}': KRUTRIM_MCP_READ_ONLY=true. "
            "Unset it or set false to allow mutations."
        )


def ensure_confirmed(confirm: bool, operation: str, resource: str) -> None:
    if confirm is not True:
        raise GuardError(
            f"Refusing guarded operation '{operation}' on '{resource}'. "
            "Re-call with confirm=true after verifying the target details."
        )
