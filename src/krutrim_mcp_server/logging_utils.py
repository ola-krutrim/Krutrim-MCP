"""Logging helpers that avoid leaking secrets."""

from __future__ import annotations

import logging
import re
import sys

_SECRET_FIELD_NAME = (
    r"(?:api[_-]?key|password|secret|secret[_-]?(?:key|access[_-]?key)|token|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
    r"client[_-]?secret(?:[_-]?value)?|authorization|private[_-]?key|"
    r"credentials?|kube[_-]?config)"
)
_SECRET_PATTERNS = (
    (
        re.compile(
            rf"([\"']?{_SECRET_FIELD_NAME}[\"']?\s*[:=]\s*[\"'])[^\"']*",
            re.IGNORECASE,
        ),
        r"\1***",
    ),
    (
        re.compile(
            rf"([\"']?{_SECRET_FIELD_NAME}[\"']?\s*[:=]\s*)(?![\"'])[^\n,}}]+",
            re.IGNORECASE,
        ),
        r"\1***",
    ),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.I), "Bearer ***"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "***JWT REDACTED***",
    ),
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.IGNORECASE | re.DOTALL,
        ),
        "***PRIVATE KEY REDACTED***",
    ),
)


def redact_text(value: str) -> str:
    """Redact common credential shapes from arbitrary text."""
    redacted = value
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        redacted = redact_text(msg)
        if redacted != msg:
            record.msg = redacted
            record.args = ()
        return True


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
        root.addHandler(handler)
    for handler in root.handlers:
        if not any(isinstance(item, RedactingFilter) for item in handler.filters):
            handler.addFilter(RedactingFilter())
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
