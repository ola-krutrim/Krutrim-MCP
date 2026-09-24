"""get_instance_task_status: the correct poll endpoint for VM-create task_ids.

get_vpc_task_status only tracks the VPC-creation task chain and returns
'Record not found' for instance task_ids (KAPI-17877); SDK 0.6.4 added
get_instance_task_status → GET /vm/v1/get_instance_task_status.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server


def _settings() -> Settings:
    return Settings(
        api_key="test-api-key-for-offline-tests",
        base_url="https://cloud.olakrutrim.com",
        default_region="In-Bangalore-1",
        read_only=False,
        log_level="WARNING",
        client_max_retries=0,
        tool_profile="admin",
    )


def test_tool_registered() -> None:
    srv = create_server(_settings())
    names = {tool.name for tool in srv._tool_manager.list_tools()}
    assert "get_instance_task_status" in names


def test_calls_sdk_with_task_id_and_region_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.get_instance_task_status.return_value = {
        "task_id": "t-1",
        "status": "success",
    }
    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    result = srv._tool_manager.get_tool("get_instance_task_status").fn(
        task_id="t-1", region="In-Bangalore-1"
    )

    assert result.ok is True
    mock_client.highlvlvpc.get_instance_task_status.assert_called_once_with(
        task_id="t-1", extra_headers={"x-region": "In-Bangalore-1"}
    )


def test_docstrings_cross_reference_each_other() -> None:
    srv = create_server(_settings())
    tools = {tool.name: tool for tool in srv._tool_manager.list_tools()}
    assert "get_instance_task_status" in (tools["get_vpc_task_status"].description or "")
    assert "get_vpc_task_status" in (
        tools["get_instance_task_status"].description or ""
    )
    assert "get_instance_task_status" in (tools["create_instance"].description or "")


def test_create_instance_timeout_error_mentions_instance_task_status() -> None:
    import inspect

    from krutrim_mcp_server.tools.compute import instances

    src = inspect.getsource(instances)
    assert "poll get_instance_task_status with the " in src
