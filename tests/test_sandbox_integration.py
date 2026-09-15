"""Sandbox tools are reachable through the guarded MCP protocol catalog."""

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.shared.memory import create_connected_server_and_client_session

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server
from tests.auth_tokens import TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN

READS = {
    "list_sandbox_templates",
    "list_sandbox_flavors",
    "list_sandboxes",
    "describe_sandbox",
    "list_sandbox_ports",
    "list_sandbox_files",
    "stat_sandbox_file",
    "read_sandbox_file",
}
ADDITIONS = {"create_sandbox", "make_sandbox_directory"}
MUTATIONS = {
    "set_sandbox_ttl",
    "delete_sandbox",
    "run_sandbox_command",
    "open_sandbox_port",
    "close_sandbox_port",
    "sandbox_proxy_request",
    "write_sandbox_file",
    "delete_sandbox_file",
    "move_sandbox_file",
}


def _settings(**overrides):
    values = {
        "api_key": None,
        "base_url": "https://cloud.olakrutrim.com",
        "read_only": False,
        "client_max_retries": 0,
        "access_token": TEST_ACCESS_TOKEN,
        "refresh_token": TEST_REFRESH_TOKEN,
        "default_region": "",
        "log_level": "ERROR",
    }
    values.update(overrides)
    return Settings(**values)


def test_sandbox_catalog_and_explicit_safety_policies():
    mcp = create_server(_settings())
    tools = {tool.name: tool for tool in mcp._tool_manager.list_tools()}
    assert READS | ADDITIONS | MUTATIONS <= tools.keys()
    for name in READS | ADDITIONS | MUTATIONS:
        tool = tools[name]
        assert tool.annotations.readOnlyHint is (name in READS)
        assert tool.annotations.destructiveHint is (name in MUTATIONS)
        assert tool.annotations.idempotentHint is (name in READS)
        if name not in READS:
            assert "confirm" in tool.parameters["required"]
    for name in ("list_sandbox_flavors", "list_sandboxes", "create_sandbox"):
        assert "region" in tools[name].parameters["required"]


@pytest.mark.asyncio
async def test_sandbox_protocol_roundtrip_uses_real_sdk(monkeypatch):
    captured = []
    stored = {}

    def handler(request):
        captured.append((request.method, request.url.path))
        assert request.url.path == "/omni/sandbox/v1/sandbox/sandbox-1/files"
        if request.method == "POST":
            stored["content"] = request.content
            return httpx.Response(200, json={"status": 200, "data": {"path": "/workspace/a.txt"}})
        return httpx.Response(200, content=stored["content"])

    server = create_server(_settings())
    with KrutrimClient(
        api_key="synthetic-test-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    ) as sdk:
        monkeypatch.setattr(get_session(), "get_client", lambda: sdk)
        async with create_connected_server_and_client_session(server._mcp_server) as client:
            args = {"sandbox_id": "sandbox-1", "path": "/workspace/a.txt"}
            result = await client.call_tool(
                "write_sandbox_file", args | {"content": "hello sandbox", "confirm": True}
            )
            assert result.isError is False
            result = await client.call_tool("read_sandbox_file", args)
            assert result.isError is False
            assert result.structuredContent["data"]["content"] == "hello sandbox"
    assert captured == [
        ("POST", "/omni/sandbox/v1/sandbox/sandbox-1/files"),
        ("GET", "/omni/sandbox/v1/sandbox/sandbox-1/files"),
    ]


@pytest.mark.asyncio
async def test_sandbox_protocol_rejects_proxy_in_read_only_mode():
    server = create_server(_settings(read_only=True))
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        tools = await client.list_tools()
        assert "sandbox_proxy_request" in {tool.name for tool in tools.tools}
        result = await client.call_tool(
            "sandbox_proxy_request",
            {"sandbox_id": "sandbox-1", "method": "GET", "path": "/health", "confirm": True},
        )
        assert result.isError is True
        assert "READ_ONLY" in result.content[0].text
