"""API-key configuration reaches actual SDK HTTP through the MCP server factory."""

from __future__ import annotations

import json
import os

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.shared.memory import create_connected_server_and_client_session

from krutrim_mcp_server import client as client_mod
from krutrim_mcp_server import logging_utils
from krutrim_mcp_server.server import create_server

_KEY = "test-api-key-for-offline-tests"


@pytest.fixture(autouse=True)
def isolated_credentials(monkeypatch):
    for name in os.environ:
        if name.upper().startswith(("KRUTRIM", "KPOD")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KRUTRIM_API_KEY", _KEY)
    yield
    logging_utils.set_redaction_secrets(())


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 401, 403])
@pytest.mark.parametrize("tool", ["list_sandbox_templates", "list_iam_roles"])
@pytest.mark.parametrize("inherited_tokens", [False, True])
async def test_configured_key_reaches_sdk_through_mcp(
    monkeypatch, status, tool, inherited_tokens,
):
    if inherited_tokens:
        monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", "obsolete-access-token")
        monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", "obsolete-refresh-token")
    requests = []
    clients = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        assert "/token/" not in request.url.path
        assert request.headers["Authorization"] == f"Bearer {_KEY}"
        assert not any("refresh" in header.lower() for header in request.headers)
        if status != 200:
            return httpx.Response(status, json={"message": f"reflected {_KEY}"})
        return httpx.Response(200, json=[{"ID": 4, "template_name": "python"}])

    def factory(**kwargs):
        assert kwargs["api_key"] == _KEY
        assert kwargs["max_retries"] == 0
        http = httpx.Client(transport=httpx.MockTransport(handler))
        sdk = KrutrimClient(http_client=http, **kwargs)
        clients.append(sdk)
        return sdk

    monkeypatch.setattr(client_mod, "KrutrimClient", factory)
    server = create_server()
    try:
        async with create_connected_server_and_client_session(server._mcp_server) as protocol:
            tools = await protocol.list_tools()
            assert len(tools.tools) == 159
            assert requests == []
            ping = await protocol.call_tool("krutrim_ping", {})
            assert ping.isError is False
            assert requests == []
            assert _KEY not in ping.model_dump_json()
            result = await protocol.call_tool(tool, {})
            assert result.isError is (status != 200)
            assert _KEY not in result.model_dump_json()
            if status == 401:
                if tool == "list_iam_roles":
                    assert "KRUTRIM_API_KEY" in result.content[0].text
                assert "KRUTRIM_ACCESS_TOKEN" not in result.content[0].text
                assert "KRUTRIM_REFRESH_TOKEN" not in result.content[0].text
            elif status == 200:
                assert "python" in json.dumps(result.structuredContent)
        assert len(requests) == 1
        assert len(clients) == 1
    finally:
        for sdk in clients:
            sdk.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("read_only, confirm", [(True, True), (False, False)])
async def test_api_key_does_not_bypass_mutation_guards(monkeypatch, read_only, confirm):
    monkeypatch.setenv("KRUTRIM_MCP_READ_ONLY", str(read_only).lower())

    def forbidden_factory(**kwargs):
        pytest.fail("Mutation guards must reject before SDK client creation")

    monkeypatch.setattr(client_mod, "KrutrimClient", forbidden_factory)
    server = create_server()
    async with create_connected_server_and_client_session(server._mcp_server) as protocol:
        result = await protocol.call_tool(
            "delete_sandbox", {"sandbox_id": "sandbox-1", "confirm": confirm},
        )
        assert result.isError is True
        assert ("READ_ONLY" if read_only else "confirm=true") in result.content[0].text
