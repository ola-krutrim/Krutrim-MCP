"""Synthetic JSON-mode serializer regressions exercised over the MCP protocol."""

from __future__ import annotations

import json
import os
from collections import namedtuple
from dataclasses import dataclass

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import CallToolResult, TextContent
from pydantic import AnyUrl, BaseModel, Field, field_serializer

from krutrim_mcp_server import logging_utils
from krutrim_mcp_server.profiles import GuardedFastMCP
from krutrim_mcp_server.serialize import to_jsonable

_URI_CASES = [
    (r"offline\opaque\credential", "https://example.invalid/offline\\opaque\\credential",
     "https://example.invalid/***REDACTED***"),
    (r"offline\opaque\credential", "file:///offline\\opaque\\credential",
     "file:///***REDACTED***"),
    ("ReviewOpaqueKey", "https://ReviewOpaqueKey.invalid/resource",
     "https://***redacted***.invalid/resource"),
]


@pytest.fixture(autouse=True)
def isolated_credentials(monkeypatch):
    for name in os.environ:
        if name.upper().startswith(("KRUTRIM", "KPOD")):
            monkeypatch.delenv(name, raising=False)
    yield
    logging_utils.set_redaction_secrets(())


def shaped_uri(value, shape):
    if shape == "nested":
        return {"nested": value}
    if shape == "mapping-key":
        return {value: "safe"}
    if shape == "list":
        return [{"nested": value}]
    if shape == "safe-string":
        return "safe-json-output"
    raise AssertionError(shape)


@pytest.mark.asyncio
@pytest.mark.parametrize("key, raw_uri, masked", _URI_CASES,
                         ids=["https-path", "file-path", "hostname"])
@pytest.mark.parametrize("shape", ["nested", "mapping-key", "list", "safe-string"])
@pytest.mark.parametrize("location", ["metadata", "structured"])
@pytest.mark.parametrize("is_error", [False, True])
@pytest.mark.parametrize("has_secrets", [False, True])
async def test_json_only_uri_serializer_preserves_semantics_and_redaction(
    key, raw_uri, masked, shape, location, is_error, has_secrets,
):
    logging_utils.set_redaction_secrets((key,) if has_secrets else ())
    uri = AnyUrl(raw_uri)
    normalized = str(uri)

    class Payload(BaseModel):
        url: AnyUrl = Field(serialization_alias="aliased_url")

        @field_serializer("url", when_used="json")
        def json_shape(self, value):
            return shaped_uri(value, shape)

    payload = Payload(url=uri)
    echoed = {"echo": payload, "plain": normalized, normalized: "plain-key"}
    original = CallToolResult(
        content=[TextContent(type="text", text=normalized)],
        structuredContent={"ok": True, "data": None}, isError=is_error,
    )
    if location == "metadata":
        original.meta = echoed
    else:
        original.structuredContent["data"] = echoed
    before = original.model_dump_json(by_alias=True)
    server = GuardedFastMCP("offline-json-uri-test")

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
    assert result.isError is is_error
    actual = result.meta if location == "metadata" else result.structuredContent["data"]
    expected_uri = masked if has_secrets else normalized
    assert actual["echo"] == {"aliased_url": shaped_uri(expected_uri, shape)}
    assert actual["plain"] == normalized
    assert actual[normalized] == "plain-key"
    assert result.content[0].text == normalized
    assert result.structuredContent["ok"] is True
    assert original.model_dump_json(by_alias=True) == before
    assert payload.url is uri
    # The source URI remains unchanged: output-only redaction, never key repair.
    assert str(uri) == normalized
    if has_secrets:
        assert key.replace("\\", "/").lower() not in json.dumps(actual["echo"]).lower()


@pytest.mark.asyncio
@pytest.mark.parametrize("key, raw_uri, masked", _URI_CASES,
                         ids=["https-path", "file-path", "hostname"])
@pytest.mark.parametrize("shape", ["normal-model", "nested", "mapping-key", "safe-string"])
@pytest.mark.parametrize("is_error", [False, True])
@pytest.mark.parametrize("has_secrets", [False, True])
async def test_to_jsonable_model_retains_uri_protection_through_mcp(
    key, raw_uri, masked, shape, is_error, has_secrets,
):
    logging_utils.set_redaction_secrets((key,) if has_secrets else ())
    uri = AnyUrl(raw_uri)
    normalized = str(uri)

    class Payload(BaseModel):
        url: AnyUrl = Field(serialization_alias="aliased_url")

    class JsonPayload(Payload):
        @field_serializer("url", when_used="json")
        def json_shape(self, value):
            return shaped_uri(value, shape)

    payload = (Payload if shape == "normal-model" else JsonPayload)(url=uri)
    before = payload.model_dump_json()
    server = GuardedFastMCP("offline-jsonable-uri-test")

    @server.tool(name="list_regions")
    def reflected():
        return CallToolResult(
            content=[TextContent(type="text", text=normalized)],
            structuredContent={"ok": True, "data": to_jsonable({
                "echo": payload, "plain": normalized, normalized: "plain-key",
            })},
            isError=is_error,
        )

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
    assert result.isError is is_error
    expected_uri = masked if has_secrets else normalized
    expected = expected_uri if shape == "normal-model" else shaped_uri(expected_uri, shape)
    actual = result.structuredContent["data"]
    # to_jsonable historically uses field names, not serialization aliases.
    assert actual["echo"] == {"url": expected}
    assert actual["plain"] == normalized
    assert actual[normalized] == "plain-key"
    assert result.content[0].text == normalized
    assert result.structuredContent["ok"] is True
    assert payload.model_dump_json() == before
    assert payload.url is uri


@pytest.mark.asyncio
@pytest.mark.parametrize("key, raw_uri, masked", _URI_CASES,
                         ids=["https-path", "file-path", "hostname"])
@pytest.mark.parametrize("slots", [False, True], ids=["dict", "slots"])
@pytest.mark.parametrize("frozen", [False, True], ids=["mutable", "frozen"])
@pytest.mark.parametrize("location", ["metadata", "structured", "to-jsonable"])
@pytest.mark.parametrize("is_error", [False, True])
@pytest.mark.parametrize("has_secrets", [False, True])
async def test_dataclass_uri_serializer_preserves_semantics_and_redaction(
    key, raw_uri, masked, slots, frozen, location, is_error, has_secrets,
):
    logging_utils.set_redaction_secrets((key,) if has_secrets else ())
    uri = AnyUrl(raw_uri)
    normalized = str(uri)

    @dataclass(slots=slots, frozen=frozen)
    class URIBox:
        url: AnyUrl
        plain: str

    class Payload(BaseModel):
        box: URIBox = Field(serialization_alias="aliased_box")

        @field_serializer("box", when_used="json")
        def json_shape(self, value):
            # The copy must retain the actual dataclass, including slots/frozen
            # behavior, rather than substituting an asdict-style mapping.
            assert type(value) is URIBox
            return {"nested": value.url, "plain": value.plain}

    box = URIBox(uri, normalized)
    payload = Payload(box=box)
    echoed = {"echo": payload, "plain": normalized, normalized: "plain-key"}
    before_payload = payload.model_dump_json()
    original = CallToolResult(
        content=[TextContent(type="text", text=normalized)],
        structuredContent={"ok": True, "data": None}, isError=is_error,
    )
    if location == "metadata":
        original.meta = echoed
    else:
        original.structuredContent["data"] = (
            to_jsonable(echoed) if location == "to-jsonable" else echoed
        )
    before_result = original.model_dump_json(by_alias=True)
    server = GuardedFastMCP("offline-dataclass-uri-test")

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
    assert result.isError is is_error
    actual = result.meta if location == "metadata" else result.structuredContent["data"]
    expected_uri = masked if has_secrets else normalized
    field_name = "box" if location == "to-jsonable" else "aliased_box"
    expected = {field_name: {"nested": expected_uri, "plain": normalized}}
    assert actual["echo"] == expected
    if location == "to-jsonable":
        # Verify the helper itself, not only the final MCP boundary's output.
        assert to_jsonable(payload) == expected
    assert actual["plain"] == normalized
    assert actual[normalized] == "plain-key"
    assert result.content[0].text == normalized
    assert result.structuredContent["ok"] is True
    assert original.model_dump_json(by_alias=True) == before_result
    assert payload.model_dump_json() == before_payload
    assert payload.box is box
    assert box.url is uri
    assert box.plain == normalized
    assert str(uri) == normalized


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["metadata", "structured", "to-jsonable"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("collision", ["uri-input", "uri-json", "normalized-key"])
async def test_serializer_collisions_never_silently_discard_entries(location, reverse, collision):
    key, raw_uri, masked = _URI_CASES[0]
    logging_utils.set_redaction_secrets((key,))

    class Payload(BaseModel):
        url: AnyUrl

        @field_serializer("url", when_used="json")
        def json_shape(self, value):
            if collision == "uri-input":
                # Sanitizing inputs must not let the serializer's own dict
                # construction silently merge formerly distinct typed keys.
                entries = [(value, "first-value"), (AnyUrl(masked), "second-value")]
            elif collision == "uri-json":
                entries = [(value, "first-value"), (masked, "second-value")]
            else:
                entries = [(b"same", "first-value"), ("same", "second-value")]
            return dict(reversed(entries) if reverse else entries)

    payload = Payload(url=AnyUrl(raw_uri))
    before = payload.model_dump_json()
    server = GuardedFastMCP("offline-json-serializer-collision")

    @server.tool(name="list_regions")
    def reflected():
        output = CallToolResult(content=[], structuredContent={"ok": True, "data": None})
        if location == "metadata":
            output.meta = {"echo": payload}
        else:
            output.structuredContent["data"] = (
                to_jsonable(payload) if location == "to-jsonable" else payload
            )
        return output

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
    assert result.isError is True
    assert result.meta is None
    assert result.structuredContent is None
    assert "first-value" not in result.model_dump_json()
    assert "second-value" not in result.model_dump_json()
    assert payload.model_dump_json() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("has_secrets", [False, True])
async def test_uri_source_copy_preserves_namedtuple_serializer_inputs(has_secrets):
    key, raw_uri, masked = _URI_CASES[0]
    logging_utils.set_redaction_secrets((key,) if has_secrets else ())
    Pair = namedtuple("Pair", "url label")

    class Payload(BaseModel):
        pair: tuple

        @field_serializer("pair", when_used="json")
        def json_shape(self, value):
            return {"url": value.url, "label": value.label}

    # Permissive SDK-like construction must not cause warnings or change the
    # Python input type observed by a JSON-only serializer.
    pair = Pair(AnyUrl(raw_uri), "safe")
    payload = Payload.model_construct(pair=pair)
    server = GuardedFastMCP("offline-namedtuple-uri-test")

    @server.tool(name="list_regions")
    def reflected():
        return CallToolResult(content=[], structuredContent={"ok": True, "data": payload})

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
    assert result.isError is False
    assert result.structuredContent["data"] == {
        "pair": {"url": masked if has_secrets else str(pair.url), "label": "safe"},
    }
    assert payload.pair is pair


@pytest.mark.parametrize("wrapper", ["direct", "to-dict", "response"])
def test_model_normalization_collision_is_not_retried_as_text(wrapper):
    class Payload(BaseModel):
        data: dict

    payload = Payload(data={None: "first-value", "null": "second-value"})

    class Response:
        status_code = 200
        text = "unsafe-fallback"

        def json(self):
            return payload

    class ToDict:
        def to_dict(self):
            return payload

        def __str__(self):
            return "unsafe-fallback"

    value = {"direct": payload, "to-dict": ToDict(), "response": Response()}[wrapper]
    with pytest.raises(ValueError, match="Ambiguous JSON mapping key"):
        to_jsonable(value)


@pytest.mark.asyncio
async def test_unmodified_json_serializer_is_not_executed_twice():
    calls = []

    class Payload(BaseModel):
        url: AnyUrl

        @field_serializer("url", when_used="json")
        def json_shape(self, value):
            calls.append(value)
            return "safe-json-output"

    logging_utils.set_redaction_secrets(())
    payload = Payload(url="https://example.invalid/safe")
    server = GuardedFastMCP("offline-single-json-serialization")

    @server.tool(name="list_regions")
    def reflected():
        return CallToolResult(content=[], structuredContent={"ok": True, "data": payload})

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
    assert result.isError is False
    assert result.structuredContent["data"] == {"url": "safe-json-output"}
    assert calls == [payload.url]
