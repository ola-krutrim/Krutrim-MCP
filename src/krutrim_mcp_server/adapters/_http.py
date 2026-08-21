"""Shared response handling for fixed-path API adapters."""

from typing import Any

import httpx


def response_payload(response: httpx.Response) -> dict[str, Any]:
    """Preserve successful raw API responses without claiming async completion."""
    if not response.content:
        return {"status_code": response.status_code, "accepted": True}
    try:
        payload = response.json()
    except ValueError:
        return {"status_code": response.status_code, "body": response.text}
    if isinstance(payload, dict):
        return payload
    return {"status_code": response.status_code, "data": payload}


def required_json_response(
    response: httpx.Response,
    *,
    expected_type: type | tuple[type, ...],
    operation: str,
) -> Any:
    """Return a verified JSON response shape for a read operation."""
    if response.status_code != 200:
        raise ValueError(
            f"{operation} returned unexpected HTTP {response.status_code}; expected 200"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError(f"{operation} returned a non-JSON response") from exc
    if not isinstance(payload, expected_type):
        expected_name = (
            "/".join(item.__name__ for item in expected_type)
            if isinstance(expected_type, tuple)
            else expected_type.__name__
        )
        raise ValueError(
            f"{operation} returned {type(payload).__name__}; expected "
            f"{expected_name}"
        )
    return payload
