"""Logging helpers that avoid leaking secrets."""

from __future__ import annotations

import logging
import re
import sys
from urllib.parse import urlsplit

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


_KNOWN_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = ()
_URI_PATH_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = ()
_URI_HOST_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = ()


def set_redaction_secrets(secrets: tuple[str, ...]) -> None:
    """Bind output-only matchers; never normalize the credentials sent to the SDK."""
    global _KNOWN_SECRET_PATTERNS, _URI_PATH_SECRET_PATTERNS, _URI_HOST_SECRET_PATTERNS
    _KNOWN_SECRET_PATTERNS = _compile_secret_patterns(secrets)
    _URI_PATH_SECRET_PATTERNS = _compile_secret_patterns(
        tuple(secret.replace("\\", "/") for secret in secrets if "\\" in secret),
    )
    _URI_HOST_SECRET_PATTERNS = _compile_secret_patterns(
        tuple(secret.lower() for secret in secrets),
    )


def _compile_secret_patterns(secrets: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    patterns = []
    for secret in secrets:
        if not secret:
            continue
        # Python repr and JSON serialization expand backslash runs and escape
        # quotes. Match those representations at any nesting depth, without
        # decoding arbitrary log text or repeatedly rewriting partial matches.
        parts = []
        for run in re.findall(r"\\+|[^\\]", secret):
            # URL parsers percent-encode credential characters (e.g. a quote).
            # Accept mixed literal/encoded forms, with case-insensitive hex only;
            # never decode surrounding text or change the SDK credential itself.
            encoded = "".join(f"%{byte:02x}" for byte in run[0].encode("utf-8"))
            encoded = "(?i:" + encoded + ")"
            if run.startswith("\\"):
                part = r"(?:\\|" + encoded + "){" + str(len(run)) + ",}"
            elif run in ("'", '"'):
                part = r"(?:\\*" + re.escape(run) + "|" + encoded + ")"
            else:
                part = "(?:" + re.escape(run) + "|" + encoded + ")"
            parts.append(part)
        patterns.append(re.compile("(?=(" + "".join(parts) + "))"))
    return tuple(patterns)


def _secret_spans(value: str, patterns: tuple[re.Pattern[str], ...]) -> list[tuple[int, int]]:
    return [match.span(1) for pattern in patterns for match in pattern.finditer(value)]


def redact_known_uri_secrets(value: str) -> str:
    """Match URL-normalized credentials only in components that normalize them.

    WHATWG special URLs fold ASCII hostnames and turn path backslashes into
    slashes. Neither rule applies to ordinary text, query strings, or fragments.
    Collect all spans before replacing so overlapping credentials stay covered.
    """
    spans = _secret_spans(value, _KNOWN_SECRET_PATTERNS)
    parts = urlsplit(value)
    if parts.scheme in {"http", "https", "ws", "wss", "ftp", "file"}:
        # Paths normalize even with an empty authority (e.g. file:///...).
        path_start = len(parts.scheme) + 1
        if value[path_start:].startswith("//"):
            path_start += 2 + len(parts.netloc)
        if parts.netloc:
            authority_start = len(parts.scheme) + 3
            host_port = parts.netloc.rsplit("@", 1)[-1]
            host_start = authority_start + len(parts.netloc) - len(host_port)
            host = host_port.split(":", 1)[0] if not host_port.startswith("[") else ""
            spans.extend((host_start + start, host_start + end)
                         for start, end in _secret_spans(host, _URI_HOST_SECRET_PATTERNS))
        spans.extend((path_start + start, path_start + end)
                     for start, end in _secret_spans(parts.path, _URI_PATH_SECRET_PATTERNS))
    return _redact_spans(value, spans)


def redact_known_secrets(value: str) -> str:
    """Replace merged original-text spans, including escaped/overlapping secrets."""
    return _redact_spans(value, _secret_spans(value, _KNOWN_SECRET_PATTERNS))


def _redact_spans(value: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return value
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    chunks: list[str] = []
    cursor = 0
    for start, end in merged:
        chunks.extend((value[cursor:start], "***REDACTED***"))
        cursor = end
    chunks.append(value[cursor:])
    return "".join(chunks)


def redact_text(value: str) -> str:
    """Redact configured opaque secrets before common credential shapes."""
    redacted = redact_known_secrets(value)
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            msg = "[Unformattable log message omitted]"
        record.msg = redact_text(msg)
        record.args = ()
        # Format exception text inside the filter; formatting it afterwards would
        # reintroduce raw exception values even when the log message is safe.
        if record.exc_info:
            record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_text(record.stack_info)
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
