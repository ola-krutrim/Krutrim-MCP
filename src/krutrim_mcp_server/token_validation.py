"""Fail-fast classification for local IAM access/refresh token pairs.

The checks in this module intentionally do not verify JWT signatures. They keep
known raw API keys and programmatic credentials out of the local stdio bearer
path before any network or SDK call. Krutrim IAM and Cloud services remain
authoritative for signature, session, revocation, MFA, and authorization.
"""

from __future__ import annotations

import base64
import json
import math
import re
import time
from typing import Any

_JWT_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_JWT_LENGTH = 8192
_PROGRAMMATIC_SCOPES = frozenset(
    {"programmatic-access", "progaccess", "service-account"}
)
_PROGRAMMATIC_MARKERS = frozenset(
    {"api-key", "api_key", "apikey", "programmatic", "programmatic-access"}
)
_ACCESS_IDENTITY_CLAIMS = ("iss", "uuid", "_id", "sid")
_ACCESS_SESSION_CLAIMS = ("aid",)
_REFRESH_SESSION_CLAIMS = ("rid", "jti")

INVALID_ACCESS_TOKEN_VALUE = (
    "Authentication configuration error: KRUTRIM_ACCESS_TOKEN must be the normal "
    "IAM session JWT returned by sign-in. API-key, programmatic-access, "
    "service-account, and malformed values are not supported."
)
INVALID_REFRESH_TOKEN_VALUE = (
    "Authentication configuration error: KRUTRIM_REFRESH_TOKEN must be the IAM "
    "refresh-token JWT returned by the same sign-in session. API-key, access-token, "
    "and malformed values are not supported."
)
TOKEN_PAIR_MISMATCH = (
    "Authentication configuration error: KRUTRIM_ACCESS_TOKEN and "
    "KRUTRIM_REFRESH_TOKEN are not from the same IAM session. Sign in again and "
    "replace both values."
)
EXPIRED_REFRESH_TOKEN = (
    "Authentication configuration error: KRUTRIM_REFRESH_TOKEN is expired. Sign in "
    "again and replace both KRUTRIM_ACCESS_TOKEN and KRUTRIM_REFRESH_TOKEN."
)


def _decode_jwt_segment(segment: str) -> bytes | None:
    if not _JWT_SEGMENT.fullmatch(segment):
        return None
    padded = segment + ("=" * (-len(segment) % 4))
    try:
        return base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except Exception:
        return None


def decode_unverified_jwt_payload(token: str) -> dict[str, Any] | None:
    """Return a structurally valid JWT payload without trusting its claims."""
    if not token or len(token) > _MAX_JWT_LENGTH:
        return None
    parts = token.split(".")
    if len(parts) != 3 or not _decode_jwt_segment(parts[2]):
        return None
    header_bytes = _decode_jwt_segment(parts[0])
    payload_bytes = _decode_jwt_segment(parts[1])
    if header_bytes is None or payload_bytes is None:
        return None
    try:
        header = json.loads(header_bytes)
        payload = json.loads(payload_bytes)
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    algorithm = header.get("alg")
    if (
        not isinstance(algorithm, str)
        or not algorithm.strip()
        or algorithm.strip().casefold() == "none"
    ):
        return None
    return payload


def _finite_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and (not isinstance(value, float) or math.isfinite(value))
    )


def _nonempty_string_claims(payload: dict[str, Any], names: tuple[str, ...]) -> bool:
    return all(
        isinstance(payload.get(name), str) and bool(payload[name].strip())
        for name in names
    )


def validate_local_access_token(
    access_token: str,
    *,
    allow_expired: bool,
    now: float | None = None,
) -> dict[str, Any]:
    """Classify a local value as a normal IAM session access token."""
    payload = decode_unverified_jwt_payload(access_token.strip())
    if payload is None:
        raise ValueError(INVALID_ACCESS_TOKEN_VALUE)

    scope = payload.get("scope")
    if not isinstance(scope, str):
        raise ValueError(INVALID_ACCESS_TOKEN_VALUE)
    scope_tokens = {token.casefold() for token in scope.split() if token}
    if scope_tokens.intersection(_PROGRAMMATIC_SCOPES):
        raise ValueError(INVALID_ACCESS_TOKEN_VALUE)
    for marker_claim in ("auth_method", "credential_type", "token_use"):
        marker = payload.get(marker_claim)
        if (
            isinstance(marker, str)
            and marker.strip().casefold() in _PROGRAMMATIC_MARKERS
        ):
            raise ValueError(INVALID_ACCESS_TOKEN_VALUE)
    if not _finite_number(payload.get("iat")) or not _finite_number(payload.get("exp")):
        raise ValueError(INVALID_ACCESS_TOKEN_VALUE)
    if not _nonempty_string_claims(
        payload,
        (*_ACCESS_IDENTITY_CLAIMS, *_ACCESS_SESSION_CLAIMS),
    ):
        raise ValueError(INVALID_ACCESS_TOKEN_VALUE)
    # This legacy claim is optional, but must remain boolean when present.
    if "sessionStatus" in payload and not isinstance(payload["sessionStatus"], bool):
        raise ValueError(INVALID_ACCESS_TOKEN_VALUE)
    if not isinstance(payload.get("isRoot"), bool):
        raise ValueError(INVALID_ACCESS_TOKEN_VALUE)

    expires_at = payload["exp"]
    if not allow_expired and expires_at <= (time.time() if now is None else now):
        raise ValueError("KRUTRIM_ACCESS_TOKEN is expired and could not be refreshed.")
    return payload


def validate_local_refresh_token(
    refresh_token: str,
    *,
    now: float | None = None,
) -> dict[str, Any]:
    """Classify a local value as an unexpired IAM refresh token."""
    payload = decode_unverified_jwt_payload(refresh_token.strip())
    if payload is None:
        raise ValueError(INVALID_REFRESH_TOKEN_VALUE)
    if not _finite_number(payload.get("iat")) or not _finite_number(payload.get("exp")):
        raise ValueError(INVALID_REFRESH_TOKEN_VALUE)
    if not _nonempty_string_claims(
        payload,
        (*_ACCESS_IDENTITY_CLAIMS, *_REFRESH_SESSION_CLAIMS),
    ):
        raise ValueError(INVALID_REFRESH_TOKEN_VALUE)
    token_type = payload.get("type")
    if not isinstance(token_type, str) or token_type.strip().casefold() != "refresh_token":
        raise ValueError(INVALID_REFRESH_TOKEN_VALUE)
    if payload["exp"] <= (time.time() if now is None else now):
        raise ValueError(EXPIRED_REFRESH_TOKEN)
    return payload


def validate_local_token_pair(
    access_token: str,
    refresh_token: str,
    *,
    allow_expired_access: bool,
    now: float | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate token classes and require one matching IAM session identity."""
    access_payload = validate_local_access_token(
        access_token,
        allow_expired=allow_expired_access,
        now=now,
    )
    refresh_payload = validate_local_refresh_token(refresh_token, now=now)
    if any(
        access_payload[claim] != refresh_payload[claim]
        for claim in _ACCESS_IDENTITY_CLAIMS
    ):
        raise ValueError(TOKEN_PAIR_MISMATCH)
    return access_payload, refresh_payload
