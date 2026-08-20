"""Serialize client responses into JSON-friendly structures for MCP tool results."""

from __future__ import annotations

import json
import re
from typing import Any

_SECRET_KEY_PATTERN = re.compile(
    r"^(?:api[_-]?key|password|secret|secret[_-]?(?:key|access[_-]?key)|"
    r"token|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
    r"client[_-]?secret(?:[_-]?value)?|authorization|private[_-]?key|"
    r"credentials?|kube[_-]?config|user[_-]?data|environment[_-]?variables)$",
    re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(r"\bBearer\s+\S+", re.IGNORECASE)
_JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_REDACTED = "***REDACTED***"


def _is_secret_key(key: Any) -> bool:
    return bool(_SECRET_KEY_PATTERN.fullmatch(str(key).strip()))


def _redact_scalar(value: str) -> str:
    if _PRIVATE_KEY_PATTERN.search(value):
        return _REDACTED
    redacted = _BEARER_PATTERN.sub("Bearer ***REDACTED***", value)
    return _JWT_PATTERN.sub(_REDACTED, redacted)


def to_jsonable(value: Any) -> Any:
    """Convert client / Pydantic / httpx responses into plain JSON-serializable data."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_scalar(value)

    if isinstance(value, dict):
        return {
            str(k): _REDACTED if _is_secret_key(k) else to_jsonable(v)
            for k, v in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]

    # Pydantic v2
    if hasattr(value, "model_dump"):
        try:
            return to_jsonable(value.model_dump(mode="json"))
        except TypeError:
            return to_jsonable(value.model_dump())

    # Pydantic v1
    if hasattr(value, "dict"):
        try:
            return to_jsonable(value.dict())
        except Exception:
            pass

    # httpx.Response
    if hasattr(value, "json") and hasattr(value, "status_code"):
        try:
            return {"status_code": value.status_code, "body": value.json()}
        except Exception:
            try:
                return {"status_code": value.status_code, "body": value.text}
            except Exception:
                return {"status_code": getattr(value, "status_code", None)}

    if hasattr(value, "to_dict"):
        try:
            return to_jsonable(value.to_dict())
        except Exception:
            pass

    # Fallback: best-effort string
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)
