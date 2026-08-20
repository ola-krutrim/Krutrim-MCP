"""Synthetic, non-secret IAM session tokens for local authentication tests."""

from __future__ import annotations

import base64
import json
from typing import Any

_FUTURE_EXPIRY = 4_102_444_800


def _jwt(payload: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    segments = []
    for part in (header, payload):
        encoded = base64.urlsafe_b64encode(json.dumps(part).encode()).decode()
        segments.append(encoded.rstrip("="))
    signature = base64.urlsafe_b64encode(b"test-signature").decode().rstrip("=")
    return ".".join([*segments, signature])


def make_iam_token_pair(
    *,
    access_exp: int | float = _FUTURE_EXPIRY,
    refresh_exp: int | float = _FUTURE_EXPIRY,
    access_overrides: dict[str, Any] | None = None,
    access_remove_claims: tuple[str, ...] = (),
    refresh_overrides: dict[str, Any] | None = None,
) -> tuple[str, str]:
    access_payload: dict[str, Any] = {
        "iat": 1_700_000_000,
        "exp": access_exp,
        "iss": "account-test",
        "uuid": "principal-test",
        "_id": "user-record-test",
        "sid": "session-test",
        "aid": "access-token-id-test",
        "sessionStatus": True,
        "scope": "cloud-console",
        "isRoot": False,
    }
    refresh_payload: dict[str, Any] = {
        "iat": 1_700_000_000,
        "exp": refresh_exp,
        "iss": "account-test",
        "uuid": "principal-test",
        "_id": "user-record-test",
        "sid": "session-test",
        "rid": "refresh-token-id-test",
        "jti": "refresh-jti-test",
        "type": "refresh_token",
    }
    if access_overrides:
        access_payload.update(access_overrides)
    for claim in access_remove_claims:
        access_payload.pop(claim, None)
    if refresh_overrides:
        refresh_payload.update(refresh_overrides)
    return _jwt(access_payload), _jwt(refresh_payload)


TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN = make_iam_token_pair()
