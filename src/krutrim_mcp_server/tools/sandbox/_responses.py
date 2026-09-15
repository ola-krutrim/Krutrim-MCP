"""Serialize Sandbox SDK responses without leaking validation diagnostics."""

from typing import Any

from pydantic import BaseModel

from krutrim_mcp_server.serialize import _is_secret_key, to_jsonable


def redact_secrets(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    """Redact known secrets using overlapping matches in the original text."""
    if not secrets:
        return value
    if isinstance(value, str):
        spans = []
        for secret in set(secrets) - {""}:
            start = value.find(secret)
            while start != -1:
                spans.append((start, start + len(secret)))
                # Advance one character to include self-overlapping occurrences.
                start = value.find(secret, start + 1)
        merged: list[tuple[int, int]] = []
        for start, end in sorted(spans):
            if merged and start < merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        parts = []
        cursor = 0
        for start, end in merged:
            parts.extend((value[cursor:start], "***REDACTED***"))
            cursor = end
        parts.append(value[cursor:])
        return "".join(parts)
    if isinstance(value, dict):
        return {
            redact_secrets(key, secrets): (
                # Key redaction must not hide a sensitive field from to_jsonable.
                "***REDACTED***" if _is_secret_key(key) else redact_secrets(item, secrets)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item, secrets) for item in value]
    return value


def safe_response(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    """Strictly validate SDK models, then redact before generic serialization."""
    try:
        if isinstance(value, BaseModel):
            # Revalidation needs aliases and Python datetime values. Never emit
            # serializer warnings: they include unredacted backend input values.
            raw = value.model_dump(mode="python", by_alias=True, warnings=False)
            value = type(value).model_validate(raw, strict=True).model_dump(
                mode="json", warnings=False
            )
        elif isinstance(value, list):
            return [safe_response(item, secrets) for item in value]
        if not isinstance(value, dict):
            raise ValueError("Expected a Sandbox response object")
        # Inspect the original envelope before redaction can change its keys.
        status = value.get("status")
        failed = status is not None and (type(status) is not int or not 200 <= status < 300)
        value = to_jsonable(redact_secrets(value, secrets))
    except Exception:
        raise ValueError("Invalid Sandbox response; response details withheld") from None
    if failed:
        raise ValueError(
            "Sandbox returned an error; response details withheld. "
            "Mutations are not retried; inspect Sandbox state before another attempt."
        )
    return value
