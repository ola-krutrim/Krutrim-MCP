"""Map Krutrim / transport errors into agent-friendly messages."""

from __future__ import annotations

from krutrim_mcp_server.logging_utils import redact_text


def format_error(exc: BaseException) -> str:
    name = type(exc).__name__
    message = redact_text(str(exc).strip() or repr(exc))

    status = getattr(exc, "status_code", None)
    if status == 401:
        return (
            "Authentication failed (401). The access-token session may need to be "
            "renewed. Complete any required IAM MFA verification or sign in again, "
            "then replace both "
            "KRUTRIM_ACCESS_TOKEN and KRUTRIM_REFRESH_TOKEN."
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
