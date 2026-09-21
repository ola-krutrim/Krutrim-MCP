"""Map Krutrim / transport errors into agent-friendly messages."""

from __future__ import annotations

from krutrim_mcp_server.logging_utils import redact_text


def _find_masked_krn_cause(exc: BaseException) -> BaseException | None:
    """Unwrap transport wrappers hiding the masked-KRN guard's ValueError.

    The wire-level guard raises inside httpx, so the SDK surfaces it as an
    APIConnectionError; walk the cause chain to recover the actionable message.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ValueError) and ":***:" in str(current):
            return current
        current = current.__cause__ or current.__context__
    return None


def format_error(exc: BaseException) -> str:
    masked = _find_masked_krn_cause(exc)
    if masked is not None:
        return redact_text(str(masked))

    name = type(exc).__name__
    message = redact_text(str(exc).strip() or repr(exc))

    status = getattr(exc, "status_code", None)
    if status == 401:
        return (
            "Authentication failed (401). Check that KRUTRIM_API_KEY contains a valid "
            "Krutrim Cloud API key, and replace it if it has expired or been revoked."
        )
    if status == 403:
        return (
            "Permission denied (403). The configured identity lacks access for this "
            "operation or region."
        )
    if status == 404:
        return f"Resource not found (404): {message}"
    if status == 429:
        return "Rate limited (429). Retry after a short backoff."
    if status is not None and int(status) >= 500:
        return f"Krutrim API server error ({status}): {message}"

    lower = message.lower()
    if "region" in lower and ("required" in lower or "missing" in lower):
        return message
    if "confirm" in lower:
        return message
    if "read-only" in lower or "read_only" in lower:
        return message

    return f"{name}: {message}"
