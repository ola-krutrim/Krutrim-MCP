"""IAM is read-only: mutation tools are not registered and point to the Cloud Console."""

from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session

from krutrim_mcp_server.client import KrutrimCloudSession
from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.profiles import (
    ADDITIVE_TOOLS,
    DESTRUCTIVE_TOOLS,
    IAM_MUTATION_TOOLS,
    READ_ONLY_TOOLS,
)
from krutrim_mcp_server.server import create_server

IAM_READS = {
    "list_iam_roles",
    "get_iam_role",
    "list_iam_policies",
    "get_iam_user",
    "list_iam_users",
    "list_iam_groups",
    "get_iam_group",
    "list_iam_group_roles",
    "list_iam_user_groups",
    "list_iam_user_roles",
}
CONSOLE_MESSAGE = "Use the Cloud Console for IAM-related mutation operations."


@pytest.fixture(params=[False, True], ids=["writable", "read-only"])
def server(monkeypatch, request):
    def no_backend(*args, **kwargs):
        pytest.fail("IAM mutation refusal must not construct a Cloud SDK client")

    monkeypatch.setattr(KrutrimCloudSession, "get_client", no_backend)
    return create_server(
        Settings(
            api_key="test-api-key-for-offline-tests",
            base_url="https://cloud.example.test",
            default_region="In-Bangalore-1",
            read_only=request.param,
            log_level="ERROR",
            client_max_retries=0,
        )
    )


def test_iam_mutations_are_not_registered_but_reads_remain(server):
    assert len(IAM_MUTATION_TOOLS) == 11
    assert IAM_MUTATION_TOOLS.isdisjoint(READ_ONLY_TOOLS | ADDITIVE_TOOLS | DESTRUCTIVE_TOOLS)
    names = {tool.name for tool in server._tool_manager.list_tools()}
    assert IAM_MUTATION_TOOLS.isdisjoint(names)
    assert IAM_READS == {name for name in names if "iam" in name}
    assert IAM_READS <= READ_ONLY_TOOLS


@pytest.mark.asyncio
async def test_iam_mutation_calls_return_console_guidance(server):
    for name in sorted(IAM_MUTATION_TOOLS):
        for arguments in ({}, {"confirm": False}, {"confirm": True, "user_id": "target"}):
            with pytest.raises(ToolError) as caught:
                await server.call_tool(name, arguments)
            assert str(caught.value) == CONSOLE_MESSAGE


@pytest.mark.asyncio
async def test_iam_mutation_guidance_over_the_mcp_protocol(server):
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        initialized = await session.initialize()
        assert CONSOLE_MESSAGE in initialized.instructions
        assert "IAM is read-only" in initialized.instructions
        assert "Do not work around" in initialized.instructions
        names = {tool.name for tool in (await session.list_tools()).tools}
        assert IAM_MUTATION_TOOLS.isdisjoint(names)
        result = await session.call_tool("create_iam_user", {"confirm": True})
        assert result.isError is True
        assert [item.text for item in result.content] == [CONSOLE_MESSAGE]


@pytest.mark.asyncio
async def test_unknown_tools_keep_the_unknown_tool_error(server):
    with pytest.raises(ToolError, match="Unknown tool"):
        await server.call_tool("not_a_real_tool", {})
