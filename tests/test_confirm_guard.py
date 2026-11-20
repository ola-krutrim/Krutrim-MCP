"""Every mutating tool refuses a non-boolean ``confirm`` before argument validation.

Pydantic's lax mode turns 1, "true", "yes" and similar into True, which used to let a
tool typed ``confirm: bool`` treat them as consent. The refusal lives in
GuardedFastMCP.call_tool, so it must hold for every registered tool.
"""

from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session

from krutrim_mcp_server.client import KrutrimCloudSession
from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server

NON_BOOLEAN = [1, 0, 1.0, "true", "True", "1", "yes", "on", "t", "false", None, [], {}]
VPC = "krn:vpc:In-Bangalore-1:7655600597:cust-uuid-1234:vpc:vpc-uuid-5678"
INSTANCE = "krn:vm:In-Bangalore-1:7655600597:cust-uuid-1234:instance:vm-uuid-1"


@pytest.fixture
def server(monkeypatch):
    def no_backend(*args, **kwargs):
        raise RuntimeError("offline test: no backend client")

    monkeypatch.setattr(KrutrimCloudSession, "get_client", no_backend)
    return create_server(
        Settings(
            api_key="test-api-key-for-offline-tests",
            base_url="https://cloud.example.test",
            default_region="In-Bangalore-1",
            read_only=False,
            log_level="ERROR",
            client_max_retries=0,
        )
    )


def _confirm_tools(server) -> list[str]:
    return sorted(
        tool.name
        for tool in server._tool_manager.list_tools()
        if "confirm" in tool.fn_metadata.arg_model.model_fields
    )


def test_every_mutating_tool_is_covered(server):
    names = _confirm_tools(server)
    # Guard against the audit silently covering nothing.
    assert len(names) >= 100
    assert {"delete_instance", "create_target_group", "delete_vm_sandbox"} <= set(names)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", NON_BOOLEAN, ids=repr)
async def test_non_boolean_confirm_is_refused_for_every_tool(server, value):
    for name in _confirm_tools(server):
        with pytest.raises(ToolError, match="confirm must be the boolean true"):
            await server.call_tool(name, {"confirm": value})


@pytest.mark.asyncio
async def test_real_booleans_pass_the_central_check(server):
    # The central check lets true/false through; later validation (missing arguments)
    # or the per-tool guard decides what happens next.
    for name in _confirm_tools(server):
        for value in (True, False):
            with pytest.raises(ToolError) as caught:
                await server.call_tool(name, {"confirm": value})
            assert "confirm must be the boolean true" not in str(caught.value)


@pytest.mark.asyncio
async def test_false_is_refused_and_omitted_confirm_is_a_required_field(server):
    arguments = {"instance_krn": INSTANCE, "region": "In-Bangalore-1"}
    with pytest.raises(ToolError, match="confirm=true") as caught:
        await server.call_tool("delete_instance", {**arguments, "confirm": False})
    assert "confirm must be the boolean true" not in str(caught.value)
    with pytest.raises(ToolError, match="confirm") as caught:
        await server.call_tool("delete_instance", arguments)
    assert "Field required" in str(caught.value)


@pytest.mark.asyncio
async def test_refusal_over_the_mcp_protocol(server):
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        await session.initialize()
        for value in (1, "true"):
            result = await session.call_tool(
                "create_target_group",
                {
                    "vpc_id": VPC,
                    "target_group_name": "confirmtest-tg",
                    "region": "In-Bangalore-1",
                    "confirm": value,
                },
            )
            assert result.isError is True
            text = "".join(getattr(item, "text", "") for item in result.content)
            assert "Re-call with confirm=true" in text
