"""Opaque authentication keys must never escape through tool output or logs."""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from krutrim_mcp_server import logging_utils
from krutrim_mcp_server.errors import format_error
from krutrim_mcp_server.serialize import to_jsonable

_KEY = "test-api-key-for-offline-tests"


@pytest.fixture
def configured_key():
    setter = getattr(logging_utils, "set_redaction_secrets", None)
    if callable(setter):
        setter((_KEY,))
    try:
        yield
    finally:
        if callable(setter):
            setter(())


def test_opaque_key_starting_with_bearer_letters_is_not_a_scheme(monkeypatch) -> None:
    from krutrim_mcp_server.config import Settings

    for name in (
        "KRUTRIM_ACCESS_TOKEN", "KRUTRIM_REFRESH_TOKEN", "KRUTRIM_CLIENT_API_KEY",
        "krutrim_client_API_KEY", "KRUTRIMCLIENT_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    key = "bearerRandomOpaqueKey_NotAHeader"
    monkeypatch.setenv("KRUTRIM_API_KEY", key)
    assert Settings.from_env().api_key == key


def test_unlabelled_api_key_is_redacted_from_text(configured_key) -> None:
    assert _KEY not in logging_utils.redact_text(f"Upstream rejected {_KEY}")


def test_unlabelled_api_key_is_redacted_from_error(configured_key) -> None:
    assert _KEY not in format_error(RuntimeError(f"Upstream reflected {_KEY}"))


def test_api_key_is_redacted_from_output_keys_and_values(configured_key) -> None:
    result = to_jsonable({f"echo-{_KEY}": [f"raw {_KEY}", {_KEY: _KEY}]})
    assert _KEY not in json.dumps(result)


def test_known_redaction_precedes_bearer_redaction(configured_key) -> None:
    # A Bearer transformation must not destroy the full known-key match first.
    text = f"Bearer prefix-{_KEY} raw={_KEY}"
    assert _KEY not in json.dumps(to_jsonable({"message": text}))


def test_http_response_body_is_redacted_recursively(configured_key) -> None:
    response = httpx.Response(200, json={"echo": _KEY, _KEY: "value"})
    assert _KEY not in json.dumps(to_jsonable(response))


def test_fallback_object_string_is_redacted(configured_key) -> None:
    class Reflected:
        def __str__(self) -> str:
            return _KEY

    assert _KEY not in json.dumps(to_jsonable(Reflected()))


def test_exception_traceback_is_redacted(configured_key) -> None:
    try:
        raise ValueError(f"Backend reflected {_KEY}")
    except ValueError:
        import sys

        record = logging.LogRecord(
            "krutrim-test", logging.ERROR, __file__, 1,
            "request failed: %s", (_KEY,), sys.exc_info(),
        )
    logging_utils.RedactingFilter().filter(record)
    assert _KEY not in logging.Formatter("%(message)s").format(record)


def test_model_serializer_warnings_do_not_expose_api_key(configured_key) -> None:
    import warnings

    from pydantic import BaseModel

    class Response(BaseModel):
        count: int

    response = Response.model_construct(count=_KEY)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = to_jsonable(response)
    assert caught == []
    assert _KEY not in json.dumps(result)


def test_overlapping_known_key_occurrences_are_fully_redacted(configured_key) -> None:
    logging_utils.set_redaction_secrets(("ababa",))
    assert logging_utils.redact_text("abababa") == "***REDACTED***"
