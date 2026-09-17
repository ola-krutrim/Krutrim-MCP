"""Offline regression coverage for escaped credentials and final MCP errors."""

from __future__ import annotations

import json
import logging
import os
import sys
from decimal import Decimal
from typing import Literal

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import (
    Annotations,
    BlobResourceContents,
    CallToolResult,
    EmbeddedResource,
    ResourceLink,
    TextContent,
    TextResourceContents,
)
from pydantic import AnyUrl, BaseModel, Field, field_serializer

from krutrim_mcp_server import client as client_mod
from krutrim_mcp_server import logging_utils
from krutrim_mcp_server import serialize as serialize_mod
from krutrim_mcp_server.profiles import GuardedFastMCP
from krutrim_mcp_server.serialize import to_jsonable
from krutrim_mcp_server.server import create_server

_KEY = r"offline\opaque\credential"
_NORMALIZED_KEY = "offline-normalization-credential"


class ReflectedModel(BaseModel):
    value: str = Field(default=_NORMALIZED_KEY, serialization_alias=_NORMALIZED_KEY)
    constant: Literal["offline-normalization-credential"] = _NORMALIZED_KEY


class JsonOnlyReflectedModel(BaseModel):
    value: str = "python-mode-safe"

    @field_serializer("value", when_used="json")
    def reflect_in_json(self, value):
        return {_NORMALIZED_KEY: _NORMALIZED_KEY.encode()}


@pytest.mark.asyncio
@pytest.mark.parametrize("payload, expected", [
    (_NORMALIZED_KEY.encode(), "***REDACTED***"),
    ({_NORMALIZED_KEY}, ["***REDACTED***"]),
    (frozenset({_NORMALIZED_KEY}), ["***REDACTED***"]),
    (ReflectedModel(), {"***REDACTED***": "***REDACTED***", "constant": "***REDACTED***"}),
    ({Decimal("1.25"): _NORMALIZED_KEY}, {"1.25": "***REDACTED***"}),
    ({_NORMALIZED_KEY.encode(): "safe"}, {"***REDACTED***": "safe"}),
    (JsonOnlyReflectedModel(), {"value": {"***REDACTED***": "***REDACTED***"}}),
], ids=[
    "bytes", "set", "frozenset", "model-alias-literal", "decimal-key", "bytes-key",
    "json-only-serializer",
])
@pytest.mark.parametrize("location", ["metadata", "structured", "extra"])
@pytest.mark.parametrize("is_error", [False, True])
async def test_final_boundary_normalizes_before_redaction(payload, expected, location, is_error):
    logging_utils.set_redaction_secrets((_NORMALIZED_KEY,))
    server = GuardedFastMCP("offline-normalization-test")
    original = CallToolResult(
        content=[TextContent(type="text", text="safe")],
        structuredContent={"ok": True, "data": None},
        isError=is_error,
    )
    if location == "metadata":
        original.meta = {"echo": payload}
    elif location == "structured":
        original.structuredContent["data"] = {"echo": payload}
    else:
        original.content[0].__pydantic_extra__["echo"] = payload

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is is_error
        if location == "metadata":
            actual = result.meta["echo"]
        elif location == "structured":
            actual = result.structuredContent["data"]["echo"]
        else:
            actual = result.content[0].model_extra["echo"]
        assert actual == expected
        assert_no_key(result.model_dump_json(), _NORMALIZED_KEY)



@pytest.mark.asyncio
async def test_only_tool_success_fields_receive_envelope_preservation():
    logging_utils.set_redaction_secrets((_NORMALIZED_KEY,))
    server = GuardedFastMCP("offline-envelope-test")

    class OtherEnvelope(BaseModel):
        value: str = Field(alias=_NORMALIZED_KEY)

    def reflected():
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text="safe")],
            structuredContent={_NORMALIZED_KEY: _NORMALIZED_KEY},
        )

    # Use FastMCP's public API to supply a non-ToolSuccess output declaration.
    reflected.__annotations__["return"] = OtherEnvelope
    server.add_tool(reflected, name="list_regions", structured_output=True)
    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is True
        assert result.structuredContent == {"***REDACTED***": "***REDACTED***"}
        assert_no_key(result.model_dump_json(), _NORMALIZED_KEY)


class UnserializableModel(BaseModel):
    value: str = _KEY

    @field_serializer("value")
    def explode(self, value):
        raise ValueError(f"Normalization failed: {value}")


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["serializer", "normalizer", "redactor", "validator"])
async def test_final_boundary_failure_returns_sanitized_tool_error(monkeypatch, failure):
    logging_utils.set_redaction_secrets((_KEY,))
    server = GuardedFastMCP("offline-failure-test")
    original = CallToolResult(
        content=[TextContent(type="text", text="safe")],
        structuredContent={"ok": True, "data": None},
        _meta={"echo": UnserializableModel() if failure == "serializer" else _KEY},
    )

    @server.tool(name="list_regions")
    def reflected():
        return original

    def explode(*args, **kwargs):
        raise ValueError(f"Boundary failed: {_KEY}")

    if failure == "normalizer":
        monkeypatch.setattr(serialize_mod._RESULT_ADAPTER, "dump_python", explode)
    elif failure == "redactor":
        monkeypatch.setattr(serialize_mod, "redact_known_secrets", explode)
    elif failure == "validator":
        validate = serialize_mod.CallToolResult.model_validate

        def fail_once(*args, **kwargs):
            # ClientSession uses this same class; fail only the server boundary.
            monkeypatch.setattr(serialize_mod.CallToolResult, "model_validate", validate)
            explode()

        monkeypatch.setattr(serialize_mod.CallToolResult, "model_validate", fail_once)

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is True
        assert result.structuredContent is None
        assert result.meta is None
        assert_no_key(result.model_dump_json(), _KEY)


@pytest.mark.parametrize("key", [
    _KEY, "\\start-and-end\\", "mixed'\"\\quotes", r"double\\backslash",
    r"literal\n-not-newline", "regex-[.*+?]-\\-key",
])
def test_serialized_key_forms_are_redacted_without_decoding_surroundings(key):
    logging_utils.set_redaction_secrets((key,))
    for form in escaped_forms(key):
        text = "unrelated \\n stays literal: " + form + " :safe suffix"
        expected = "unrelated \\n stays literal: ***REDACTED*** :safe suffix"
        assert logging_utils.redact_known_secrets(text) == expected
        assert to_jsonable({text: text}) == {expected: expected}


def escaped_forms(key):
    """Include recoverable Python/JSON representations, also nested by logs."""
    forms = {key}
    for _ in range(3):
        forms |= {repr(value)[1:-1] for value in forms}
        forms |= {json.dumps(value)[1:-1] for value in forms}
    return forms


def assert_no_key(value, key):
    for escaped in escaped_forms(key):
        assert escaped not in value


@pytest.fixture(autouse=True)
def isolated_credentials(monkeypatch):
    for name in os.environ:
        if name.upper().startswith(("KRUTRIM", "KPOD")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KRUTRIM_API_KEY", _KEY)
    monkeypatch.setattr(client_mod, "_session", None)
    yield
    logging_utils.set_redaction_secrets(())


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 500])
@pytest.mark.parametrize("body_encoding", ["plain", "repr", "json"])
@pytest.mark.parametrize("key", [
    "offline-ordinary-credential", _KEY, 'offline"uri-credential', "ReviewOpaqueKey",
])
async def test_escaped_sdk_error_is_redacted_on_mcp(monkeypatch, status, body_encoding, key):
    monkeypatch.setenv("KRUTRIM_API_KEY", key)
    requests = []
    clients = []

    def handler(request):
        requests.append(request)
        # Keys are accepted and transmitted unchanged, not repaired to avoid leaks.
        assert request.headers["Authorization"] == f"Bearer {key}"
        reflected = {"plain": key, "repr": repr(key), "json": json.dumps(key)}
        return httpx.Response(status, json={"message": reflected[body_encoding]})

    def factory(**kwargs):
        assert kwargs["api_key"] == key
        sdk = KrutrimClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)),
                            **kwargs)
        clients.append(sdk)
        return sdk

    monkeypatch.setattr(client_mod, "KrutrimClient", factory)
    server = create_server()
    try:
        async with create_connected_server_and_client_session(server._mcp_server) as protocol:
            result = await protocol.call_tool("list_iam_roles", {})
            assert result.isError is True
            assert str(status) in result.content[0].text
            for content in result.content:
                assert_no_key(content.text, key)
            assert_no_key(result.model_dump_json(), key)
        assert len(requests) == 1
    finally:
        for sdk in clients:
            sdk.close()


@pytest.mark.parametrize("encoding", [repr, json.dumps])
def test_escaped_dict_logs_and_tracebacks_are_redacted(encoding):
    logging_utils.set_redaction_secrets((_KEY,))
    try:
        raise ValueError(encoding({"reflected": _KEY}))
    except ValueError:
        record = logging.LogRecord(
            "krutrim_client", logging.ERROR, __file__, 1,
            "SDK body: %s", ({"reflected": _KEY},), sys.exc_info(),
        )
    logging_utils.RedactingFilter().filter(record)
    rendered = logging.Formatter("%(message)s").format(record)
    assert "SDK body" in rendered
    assert "ValueError" in rendered
    assert_no_key(rendered, _KEY)


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["offline-ordinary-credential", _KEY])
async def test_framework_argument_errors_are_redacted(monkeypatch, key):
    monkeypatch.setenv("KRUTRIM_API_KEY", key)

    def forbidden_factory(**kwargs):
        pytest.fail("Invalid region must be rejected before SDK access")

    monkeypatch.setattr(client_mod, "KrutrimClient", forbidden_factory)
    server = create_server()
    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_vpcs", {"region": key})
        assert result.isError is True
        assert "region" in result.content[0].text
        assert "validation" in result.content[0].text.lower()
        assert_no_key(result.content[0].text, key)
        assert_no_key(result.model_dump_json(), key)


@pytest.mark.asyncio
@pytest.mark.parametrize("validation_layer", ["pydantic", "jsonschema"])
async def test_framework_output_schema_errors_are_redacted(validation_layer):
    logging_utils.set_redaction_secrets((_KEY,))
    server = GuardedFastMCP("offline-boundary-test")

    @server.tool(name="list_regions")
    def reflected():
        if validation_layer == "pydantic":
            return {"ok": _KEY, "data": None}
        return {"ok": True, "data": _KEY}

    if validation_layer == "jsonschema":
        # Keep FastMCP's Any-valued data model, but constrain the published schema
        # to exercise the *later* low-level protocol output validation boundary.
        server._tool_manager.get_tool("list_regions").output_schema["properties"]["data"] = {
            "type": "integer",
        }
    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is True
        assert "validation" in result.content[0].text.lower()
        assert_no_key(result.content[0].text, _KEY)
        assert_no_key(result.model_dump_json(), _KEY)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_error", [False, True])
async def test_final_tool_result_preserves_protocol_metadata(is_error):
    logging_utils.set_redaction_secrets((_KEY,))
    server = GuardedFastMCP("offline-boundary-test")
    original = CallToolResult(
        content=[TextContent(
            type="text", text=f"reflected {repr(_KEY)}",
            annotations=Annotations(audience=["user"], priority=0.5),
            _meta={"echo": _KEY, "keep": "content metadata"},
        )],
        structuredContent={"ok": True, "data": {_KEY: _KEY, "count": 2}},
        isError=is_error,
        _meta={"echo": _KEY, "keep": "result metadata"},
    )

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        catalog = await protocol.list_tools()
        assert catalog.tools[0].annotations.readOnlyHint is True
        assert catalog.tools[0].annotations.destructiveHint is False
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is is_error
        assert result.structuredContent["ok"] is True
        assert result.structuredContent["data"]["count"] == 2
        assert result.content[0].annotations == original.content[0].annotations
        assert result.content[0].meta["keep"] == "content metadata"
        assert result.meta["keep"] == "result metadata"
        assert_no_key(result.content[0].text, _KEY)
        assert_no_key(result.model_dump_json(), _KEY)
    # Redaction must not mutate SDK/tool-owned result objects.
    assert original.meta["echo"] == _KEY
    assert original.structuredContent["data"][_KEY] == _KEY


@pytest.mark.asyncio
@pytest.mark.parametrize("is_error", [False, True])
async def test_final_metadata_tuple_is_redacted(is_error):
    key = "offline-tuple-credential"
    logging_utils.set_redaction_secrets((key,))
    server = GuardedFastMCP("offline-boundary-test")
    original = CallToolResult(
        content=[TextContent(type="text", text="safe")],
        structuredContent={"ok": True, "data": None},
        isError=is_error,
        _meta={"echo": (key, {"nested": (key,)})},
    )

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is is_error
        assert result.meta["echo"] == [
            "***REDACTED***", {"nested": ["***REDACTED***"]},
        ]
        assert_no_key(result.model_dump_json(), key)
    assert original.meta["echo"] == (key, {"nested": (key,)})


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["structured", "metadata", "extra"])
@pytest.mark.parametrize("shape", ["value", "nested", "mapping-key", "model"])
@pytest.mark.parametrize("is_error", [False, True])
@pytest.mark.parametrize("key, raw_uri, masked", [
    (_KEY, "https://example.invalid/" + _KEY, "https://example.invalid/***REDACTED***"),
    (_KEY, "file:///" + _KEY, "file:///***REDACTED***"),
    ("ReviewOpaqueKey", "https://ReviewOpaqueKey.invalid/resource",
     "https://***redacted***.invalid/resource"),
], ids=["https-path", "file-path", "hostname"])
async def test_arbitrary_anyurl_retains_uri_redaction_provenance(
    location, shape, is_error, key, raw_uri, masked,
):
    logging_utils.set_redaction_secrets((key,))
    server = GuardedFastMCP("offline-payload-uri-test")
    uri = AnyUrl(raw_uri)
    normalized = str(uri)

    class Payload(BaseModel):
        url: AnyUrl = Field(serialization_alias="aliased_url")

    payload, expected = {
        "value": ({"url": uri}, {"url": masked}),
        "nested": ({1: ({"url": uri},)}, {"1": [{"url": masked}]}),
        "mapping-key": ({uri: {"url": uri}}, {masked: {"url": masked}}),
        "model": (Payload(url=uri), {"aliased_url": masked}),
    }[shape]
    # Identical ordinary strings must not acquire URI-only transformations.
    echoed = {"echo": payload, "plain": normalized, normalized: "plain key"}
    original = CallToolResult(
        content=[TextContent(type="text", text=normalized)],
        structuredContent={"ok": True, "data": None}, isError=is_error,
    )
    if location == "structured":
        original.structuredContent["data"] = echoed
    elif location == "metadata":
        original.meta = echoed
    else:
        original.content[0].__pydantic_extra__["payload"] = echoed
    before = original.model_dump(mode="python", by_alias=True)

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is is_error
        if location == "structured":
            actual = result.structuredContent["data"]
        elif location == "metadata":
            actual = result.meta
        else:
            actual = result.content[0].model_extra["payload"]
        assert actual["echo"] == expected
        assert key.replace("\\", "/").lower() not in json.dumps(actual["echo"]).lower()
        assert actual["plain"] == normalized
        assert actual[normalized] == "plain key"
        assert result.content[0].text == normalized
    assert original.model_dump(mode="python", by_alias=True) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["link", "embedded_text", "embedded_blob"])
@pytest.mark.parametrize("is_error", [False, True])
@pytest.mark.parametrize("key", [
    "offline-uri-credential", 'offline"uri-credential', r"review\opaque\credential",
])
@pytest.mark.parametrize("base", ["https://example.invalid/", "file:///"])
async def test_final_resource_uri_is_redacted(kind, is_error, key, base):
    logging_utils.set_redaction_secrets((key,))
    server = GuardedFastMCP("offline-boundary-test")
    uri = f"{base}{key}"
    annotations = Annotations(audience=["user"], priority=0.5)
    if kind == "link":
        content = ResourceLink(type="resource_link", name="safe", uri=uri,
                               annotations=annotations)
    else:
        resource = (
            TextResourceContents(uri=uri, text="safe") if kind == "embedded_text"
            else BlobResourceContents(uri=uri, blob="c2FmZQ==")
        )
        content = EmbeddedResource(type="resource", resource=resource,
                                   annotations=annotations)
    original = CallToolResult(
        content=[content], structuredContent={"ok": True, "data": None}, isError=is_error,
    )

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is is_error
        returned = result.content[0]
        assert returned.type == content.type
        assert returned.annotations == annotations
        returned_uri = returned.uri if kind == "link" else returned.resource.uri
        assert str(returned_uri) == base + "***REDACTED***"
        assert_no_key(result.model_dump_json(), key)
    original_uri = content.uri if kind == "link" else content.resource.uri
    assert str(original_uri) == uri.replace('"', "%22").replace("\\", "/")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["link", "embedded_text", "embedded_blob"])
@pytest.mark.parametrize("is_error", [False, True])
async def test_final_resource_hostname_normalization_is_redacted(kind, is_error):
    key = "ReviewOpaqueKey"
    logging_utils.set_redaction_secrets((key,))
    server = GuardedFastMCP("offline-hostname-test")
    uri = f"https://{key}.invalid/{key.lower()}"
    if kind == "link":
        content = ResourceLink(type="resource_link", name="safe", uri=uri)
    else:
        resource = (
            TextResourceContents(uri=uri, text="safe") if kind == "embedded_text"
            else BlobResourceContents(uri=uri, blob="c2FmZQ==")
        )
        content = EmbeddedResource(type="resource", resource=resource)
    original = CallToolResult(
        content=[content, TextContent(type="text", text=key.lower())],
        structuredContent={"ok": True, "data": {"plain": key.lower()}},
        isError=is_error,
    )

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is is_error
        returned = result.content[0]
        returned_uri = returned.uri if kind == "link" else returned.resource.uri
        assert returned_uri.host == "***redacted***.invalid"
        # Case-insensitive matching is exclusive to the hostname, not opaque text/path.
        assert returned_uri.path == f"/{key.lower()}"
        assert result.content[1].text == key.lower()
        assert result.structuredContent["data"]["plain"] == key.lower()
    original_uri = content.uri if kind == "link" else content.resource.uri
    assert original_uri.host == f"{key.lower()}.invalid"
    assert logging_utils.redact_known_secrets(key.lower()) == key.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["https", "https://example.invalid/credential"])
async def test_uri_redaction_remains_valid_when_scheme_is_secret(key):
    logging_utils.set_redaction_secrets((key,))
    server = GuardedFastMCP("offline-boundary-test")

    @server.tool(name="list_regions")
    def reflected():
        return CallToolResult(
            content=[ResourceLink(type="resource_link", name="safe",
                                  uri="https://example.invalid/credential")],
            structuredContent={"ok": True, "data": None},
        )

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is False
        assert result.content[0].type == "resource_link"
        assert str(result.content[0].uri) == "redacted:***REDACTED***"
        assert_no_key(result.model_dump_json(), key)


@pytest.mark.asyncio
@pytest.mark.parametrize("map_key, json_key", [
    (1, "1"), (False, "false"), (None, "null"), (1.5, "1.5"), ("None", "None"),
])
@pytest.mark.parametrize("is_error", [False, True])
async def test_final_metadata_normalizes_json_object_keys(map_key, json_key, is_error):
    key = "offline-mapping-credential"
    logging_utils.set_redaction_secrets((key,))
    server = GuardedFastMCP("offline-boundary-test")
    original = CallToolResult(
        content=[TextContent(type="text", text="safe")],
        structuredContent={"ok": True, "data": None},
        isError=is_error,
        _meta={"echo": {map_key: key}},
    )

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is is_error
        assert result.meta["echo"] == {json_key: "***REDACTED***"}
        assert_no_key(result.model_dump_json(), key)
    assert original.meta["echo"] == {map_key: key}


@pytest.mark.asyncio
@pytest.mark.parametrize("map_key, json_key", [
    (1, "1"), (False, "false"), (1.5, "1.5"), (b"outer", "outer"),
    (Decimal("1.25"), "1.25"),
])
@pytest.mark.parametrize("is_error", [False, True])
async def test_nested_nonstring_ancestors_preserve_null_key_provenance(map_key, json_key, is_error):
    logging_utils.set_redaction_secrets((_KEY,))
    server = GuardedFastMCP("offline-null-provenance-test")
    nested = {map_key: ({None: _KEY}, {"None": "literal-string-key"})}
    original = CallToolResult(
        content=[TextContent(type="text", text="safe")],
        structuredContent={"ok": True, "data": {"echo": nested}},
        _meta={"echo": nested}, isError=is_error,
    )

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        expected = {json_key: [{"null": "***REDACTED***"}, {"None": "literal-string-key"}]}
        assert result.isError is is_error
        assert result.meta["echo"] == expected
        assert result.structuredContent["data"]["echo"] == expected
        assert_no_key(result.model_dump_json(), _KEY)
    assert original.meta["echo"][map_key][0] == {None: _KEY}


@pytest.mark.asyncio
@pytest.mark.parametrize("location, uri_keys", [
    ("structured", False), ("metadata", False), ("extra", False), ("to-jsonable", False),
    ("structured", True), ("metadata", True), ("extra", True),
])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
async def test_redaction_key_collisions_fail_closed(location, nested, reverse, uri_keys):
    key = _KEY if uri_keys else "offline-collision-credential"
    logging_utils.set_redaction_secrets((key,))
    server = GuardedFastMCP("offline-redaction-collision-test")
    first_key = AnyUrl("https://example.invalid/" + key) if uri_keys else key
    second_key = "https://example.invalid/***REDACTED***" if uri_keys else "***REDACTED***"
    entries = [(first_key, "first value"), (second_key, "second value")]
    mapping = dict(reversed(entries) if reverse else entries)
    payload = {1: [{"nested": mapping}]} if nested else mapping
    original = CallToolResult(
        content=[TextContent(type="text", text="safe")],
        structuredContent={"ok": True, "data": None},
    )
    if location == "structured":
        original.structuredContent["data"] = payload
    elif location == "metadata":
        original.meta = {"echo": payload}
    elif location == "extra":
        original.content[0].__pydantic_extra__["echo"] = payload

    @server.tool(name="list_regions")
    def reflected():
        if location == "to-jsonable":
            return {"ok": True, "data": to_jsonable(payload)}
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
    assert result.isError is True
    assert result.structuredContent is None
    assert result.meta is None
    assert_no_key(result.model_dump_json(), key)
    assert "first value" not in result.model_dump_json()
    assert "second value" not in result.model_dump_json()
    if location != "to-jsonable":
        assert result.content == []
    assert list(mapping.items()) == (list(reversed(entries)) if reverse else entries)


@pytest.mark.parametrize("wrapper", ["dict", "model", "response", "to-dict"])
@pytest.mark.parametrize("reverse", [False, True])
def test_to_jsonable_rejects_redaction_collisions_without_fallback(wrapper, reverse):
    key = "offline-collision-credential"
    logging_utils.set_redaction_secrets((key,))
    entries = [(key, "first value"), ("***REDACTED***", "second value")]
    mapping = dict(reversed(entries) if reverse else entries)

    class Payload(BaseModel):
        data: dict

    class Response:
        def to_dict(self):
            return mapping

    value = {
        "dict": mapping,
        "model": Payload(data=mapping),
        "response": httpx.Response(200, json=mapping),
        "to-dict": Response(),
    }[wrapper]
    with pytest.raises(ValueError, match="Ambiguous JSON mapping key"):
        to_jsonable(value)


@pytest.mark.asyncio
@pytest.mark.parametrize("keys", [("ok", "data"), ("content",), ("text",)])
async def test_preserved_schema_fields_do_not_create_redaction_collisions(keys):
    logging_utils.set_redaction_secrets(keys)
    server = GuardedFastMCP("offline-schema-collision-test")
    original = CallToolResult(
        content=[TextContent(type="text", text="safe", **{"***REDACTED***": "safe"})],
        structuredContent={"ok": True, "data": None},
        **{"***REDACTED***": "safe"},
    )

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
    assert result.isError is False
    assert result.structuredContent == original.structuredContent
    assert result.content[0].text == "safe"
    assert result.content[0].model_extra == {"***REDACTED***": "safe"}
    assert result.model_extra == {"***REDACTED***": "safe"}


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("ancestor", ["outer", 1, b"outer", Decimal("1.25")])
async def test_null_and_literal_none_key_collision_never_loses_data(reverse, ancestor):
    logging_utils.set_redaction_secrets((_KEY,))
    server = GuardedFastMCP("offline-null-collision-test")
    entries = [(None, f"null-value:{_KEY}"), ("None", "string-value")]
    nested = {ancestor: dict(reversed(entries) if reverse else entries)}
    original = CallToolResult(
        content=[TextContent(type="text", text="safe")],
        structuredContent={"ok": True, "data": None}, _meta={"echo": nested},
    )

    @server.tool(name="list_regions")
    def reflected():
        return original

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        if result.isError:
            assert result.content == []
            assert result.meta is None
            assert result.structuredContent is None
        else:
            value = next(iter(result.meta["echo"].values()))
            assert value == {"null": "null-value:***REDACTED***", "None": "string-value"}
        assert_no_key(result.model_dump_json(), _KEY)
    assert len(original.meta["echo"][ancestor]) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["ok", "data"])
async def test_production_list_regions_preserves_declared_envelope(monkeypatch, key):
    monkeypatch.setenv("KRUTRIM_API_KEY", key)

    def forbidden_factory(**kwargs):
        pytest.fail("list_regions must not access the Cloud SDK")

    monkeypatch.setattr(client_mod, "KrutrimClient", forbidden_factory)
    server = create_server()
    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        catalog = await protocol.list_tools()
        declaration = next(tool for tool in catalog.tools if tool.name == "list_regions")
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is False
        assert set(result.structuredContent) == {"ok", "data"}
        assert result.structuredContent["ok"] is True
        assert result.structuredContent["data"]["regions"] == [
            "In-Bangalore-1", "In-Hyderabad-1",
        ]
        assert json.loads(result.content[0].text) == result.structuredContent
        assert declaration.outputSchema["properties"]["ok"]["const"] is True
        assert set(declaration.outputSchema["properties"]) == {"ok", "data"}
        assert declaration.annotations.readOnlyHint is True
        assert declaration.annotations.destructiveHint is False


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["isError", "content", "text", "user", "ok", "data"])
@pytest.mark.parametrize("is_error", [False, True])
async def test_redaction_preserves_protocol_fields_and_constants(key, is_error):
    # The key contract does not impose a length minimum or reserve MCP words.
    logging_utils.set_redaction_secrets((key,))
    server = GuardedFastMCP("offline-boundary-test")

    @server.tool(name="list_regions")
    def reflected():
        return CallToolResult(
            isError=is_error,
            content=[TextContent(
                type="text", text=key,
                annotations=Annotations(audience=["user"], priority=0.5),
            )],
            structuredContent={"ok": True, "data": {key: key}},
            _meta={key: key, "nested": {key: key}},
        )

    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool("list_regions", {})
        assert result.isError is is_error
        assert result.meta == {
            "***REDACTED***": "***REDACTED***",
            "nested": {"***REDACTED***": "***REDACTED***"},
        }
        assert result.content[0].type == "text"
        assert result.content[0].text == "***REDACTED***"
        assert result.content[0].annotations.audience == ["user"]
        assert result.structuredContent == {
            "ok": True, "data": {"***REDACTED***": "***REDACTED***"},
        }
