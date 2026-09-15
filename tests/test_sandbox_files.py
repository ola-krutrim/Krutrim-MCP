"""Sandbox file operations use the real SDK with an in-memory HTTP transport."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.server import Settings as FastMCPSettings


@pytest.fixture
def harness(monkeypatch):
    try:
        module = importlib.import_module("krutrim_mcp_server.tools.sandbox.files")
    except ModuleNotFoundError:
        pytest.fail("Sandbox file tools are not implemented")
    requests = []
    state = SimpleNamespace(read_only=False, response=None, error=None)

    def handler(request):
        requests.append(request)
        if state.error:
            raise state.error
        if state.response is not None:
            return state.response
        return httpx.Response(200, json={"status": 200, "data": {"path": "/workspace/a.txt"}})

    client = KrutrimClient(
        api_key="synthetic-test-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    session = SimpleNamespace(settings=state, get_client=lambda: client)
    monkeypatch.setattr(module, "get_session", lambda: session)
    monkeypatch.setattr(module, "settings", lambda: state)
    FastMCPSettings.model_rebuild()
    mcp = FastMCP("sandbox-file-test")
    module.register(mcp)
    yield mcp, state, requests
    client.close()


def test_delete_sandbox_file_contract(harness):
    mcp, _, requests = harness
    tool = mcp._tool_manager.get_tool("delete_sandbox_file")
    assert tool is not None
    result = tool.fn(sandbox_id="sandbox-1", path="/workspace/a.txt", confirm=True)
    assert result.ok
    assert requests[0].method == "DELETE"
    assert requests[0].url.path == "/omni/sandbox/v1/sandbox/sandbox-1/files"
    assert dict(requests[0].url.params) == {"path": "/workspace/a.txt"}


def test_move_sandbox_file_contract(harness):
    mcp, _, requests = harness
    tool = mcp._tool_manager.get_tool("move_sandbox_file")
    assert tool is not None
    result = tool.fn(
        sandbox_id="sandbox-1", path="/workspace/a.txt", confirm=True, new_path="/workspace/b.txt"
    )
    assert result.ok
    assert requests[0].method == "PUT"
    assert requests[0].url.path == "/omni/sandbox/v1/sandbox/sandbox-1/files/move"
    assert dict(requests[0].url.params) == {
        "path": "/workspace/a.txt",
        "newPath": "/workspace/b.txt",
    }


def test_make_sandbox_directory_contract(harness):
    mcp, _, requests = harness
    tool = mcp._tool_manager.get_tool("make_sandbox_directory")
    assert tool is not None
    result = tool.fn(sandbox_id="sandbox-1", path="/workspace/a.txt", confirm=True)
    assert result.ok
    assert requests[0].method == "POST"
    assert requests[0].url.path == "/omni/sandbox/v1/sandbox/sandbox-1/dirs"
    assert dict(requests[0].url.params) == {"path": "/workspace/a.txt"}


_MUTATIONS = [
    ("write_sandbox_file", {"content": "hello"}),
    ("delete_sandbox_file", {}),
    ("move_sandbox_file", {"new_path": "/workspace/b.txt"}),
    ("make_sandbox_directory", {}),
]


@pytest.mark.parametrize(("name", "extra"), _MUTATIONS)
@pytest.mark.parametrize(("read_only", "confirm"), [(True, True), (False, False), (False, "true")])
def test_file_mutations_are_guarded_before_http(harness, name, extra, read_only, confirm):
    mcp, state, requests = harness
    state.read_only = read_only
    with pytest.raises(ToolError, match="confirm|READ_ONLY"):
        mcp._tool_manager.get_tool(name).fn(
            sandbox_id="sandbox-1", path="/workspace/a.txt", confirm=confirm, **extra
        )
    assert not requests


@pytest.mark.parametrize(("name", "extra"), _MUTATIONS)
def test_file_mutations_never_retry_uncertain_timeouts(harness, name, extra):
    mcp, state, requests = harness
    state.error = httpx.ReadTimeout("uncertain result")
    with pytest.raises(ToolError):
        mcp._tool_manager.get_tool(name).fn(
            sandbox_id="sandbox-1", path="/workspace/a.txt", confirm=True, **extra
        )
    assert len(requests) == 1


@pytest.mark.parametrize("status", [200, 500])
def test_upload_envelope_never_reflects_content(harness, status):
    mcp, state, requests = harness
    state.response = httpx.Response(
        200,
        json={
            "status": status,
            "message": "echo opaque-upload-secret",
            "extra": "opaque-upload-secret",
            "data": {"path": "/workspace/a.txt", "echo": "opaque-upload-secret"},
        },
    )
    tool = mcp._tool_manager.get_tool("write_sandbox_file")
    args = dict(
        sandbox_id="sandbox-1",
        path="/workspace/a.txt",
        content="opaque-upload-secret",
        confirm=True,
    )
    if status == 500:
        with pytest.raises(ToolError) as error:
            tool.fn(**args)
        assert "opaque-upload-secret" not in str(error.value)
        assert "withheld" in str(error.value)
    else:
        result = tool.fn(**args)
        assert "opaque-upload-secret" not in result.model_dump_json()
        assert result.data["data"]["path"] == "/workspace/a.txt"
    assert len(requests) == 1
    assert requests[0].content == b"opaque-upload-secret"


def test_file_upload_error_does_not_echo_file_content(harness):
    mcp, state, _ = harness
    state.response = httpx.Response(400, json={"message": "uploaded synthetic-sensitive-value"})
    with pytest.raises(ToolError) as error:
        mcp._tool_manager.get_tool("write_sandbox_file").fn(
            sandbox_id="sandbox-1",
            path="/workspace/a.txt",
            content="synthetic-sensitive-value",
            confirm=True,
        )
    assert "synthetic-sensitive-value" not in str(error.value)
    assert "400" in str(error.value)


def test_write_sandbox_file_sends_literal_utf8_not_a_host_path(harness):
    mcp, _, requests = harness
    tool = mcp._tool_manager.get_tool("write_sandbox_file")
    assert tool is not None, "write_sandbox_file must be registered"
    result = tool.fn(
        sandbox_id="sandbox-1", path="/workspace/a.txt", content="/etc/passwd\nनमस्ते", confirm=True
    )
    assert result.ok
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert request.url.path == "/omni/sandbox/v1/sandbox/sandbox-1/files"
    assert dict(request.url.params) == {"path": "/workspace/a.txt"}
    assert request.headers["content-type"] == "application/octet-stream"
    assert request.content == "/etc/passwd\nनमस्ते".encode()


@pytest.mark.parametrize(
    "overrides",
    [
        {"sandbox_id": "../other"},
        {"sandbox_id": "a/b"},
        {"sandbox_id": "a%2fb"},
        {"sandbox_id": "a?b"},
        {"sandbox_id": " a"},
        {"sandbox_id": "a\\b"},
        {"path": ""},
        {"path": "/workspace/../etc/passwd"},
        {"path": "a\x00b"},
        {"path": " /tmp/a"},
        {"content": "x" * (1024 * 1024 + 1)},
        {"content": 42},
    ],
)
def test_write_rejects_invalid_input_before_http(harness, overrides):
    mcp, _, requests = harness
    args = dict(sandbox_id="sandbox-1", path="/workspace/a.txt", content="hello", confirm=True)
    args.update(overrides)
    with pytest.raises(ToolError):
        mcp._tool_manager.get_tool("write_sandbox_file").fn(**args)
    assert not requests


@pytest.mark.parametrize("content", [b"hello", "नमस्ते".encode(), b""])
def test_read_sandbox_file_returns_utf8(harness, content):
    mcp, state, requests = harness
    state.response = httpx.Response(200, content=content)
    tool = mcp._tool_manager.get_tool("read_sandbox_file")
    assert tool is not None
    result = tool.fn(sandbox_id="sandbox-1", path="/workspace/a.txt")
    assert result.data == {
        "path": "/workspace/a.txt",
        "content": content.decode(),
        "size_bytes": len(content),
    }
    assert requests[0].method == "GET"
    assert requests[0].url.path == "/omni/sandbox/v1/sandbox/sandbox-1/files"
    assert dict(requests[0].url.params) == {"path": "/workspace/a.txt"}


@pytest.mark.parametrize(
    "content", [b"x" * (1024 * 1024 + 1), b"\xff\x00"], ids=["oversized", "binary"]
)
def test_read_rejects_oversized_or_binary_files(harness, content):
    mcp, state, _ = harness
    state.response = httpx.Response(200, content=content)
    tool = mcp._tool_manager.get_tool("read_sandbox_file")
    assert tool is not None
    with pytest.raises(ToolError, match="1 MiB|UTF-8"):
        tool.fn(sandbox_id="sandbox-1", path="/workspace/a.txt")


def test_read_redacts_credentials_in_text(harness):
    mcp, state, _ = harness
    state.response = httpx.Response(200, text="password=synthetic-sensitive-value\nhello")
    tool = mcp._tool_manager.get_tool("read_sandbox_file")
    assert tool is not None
    result = tool.fn(sandbox_id="sandbox-1", path="/workspace/a.txt")
    assert "synthetic-sensitive-value" not in result.data["content"]
    assert "hello" in result.data["content"]


@pytest.mark.parametrize(
    ("name", "suffix", "extra", "data"),
    [
        ("list_sandbox_files", "/files/list", {"depth": 2}, []),
        ("stat_sandbox_file", "/files/stat", {}, {"path": "/workspace", "type": "dir"}),
    ],
)
def test_file_metadata_wire_contract(harness, name, suffix, extra, data):
    mcp, state, requests = harness
    state.read_only = True
    state.response = httpx.Response(200, json={"status": 200, "data": data})
    tool = mcp._tool_manager.get_tool(name)
    assert tool is not None
    result = tool.fn(sandbox_id="sandbox-1", path="/workspace", **extra)
    assert result.ok
    assert requests[0].method == "GET"
    assert requests[0].url.path == "/omni/sandbox/v1/sandbox/sandbox-1" + suffix
    assert dict(requests[0].url.params) == {
        "path": "/workspace",
        **{k: str(v) for k, v in extra.items()},
    }


@pytest.mark.parametrize("depth", [True, 0, 11, "2"])
def test_file_list_depth_is_strict_and_bounded(harness, depth):
    mcp, _, requests = harness
    tool = mcp._tool_manager.get_tool("list_sandbox_files")
    assert tool is not None
    with pytest.raises(ToolError):
        tool.fn(sandbox_id="sandbox-1", path="/workspace", depth=depth)
    assert not requests
