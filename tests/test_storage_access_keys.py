"""Safety and tier-routing tests for object-storage access keys."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from krutrim_client.types.kos.accessKeys.access_keys_list_response import (
    AccessKeyListResponseItem,
)
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server
from tests.auth_tokens import TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN


def _settings() -> Settings:
    return Settings(
        api_key=None,
        base_url="https://cloud.olakrutrim.com",
        default_region="In-Bangalore-1",
        read_only=False,
        log_level="WARNING",
        client_max_retries=0,
        tool_profile="admin",
        enable_sensitive_tools=True,
        access_token=TEST_ACCESS_TOKEN,
        refresh_token=TEST_REFRESH_TOKEN,
    )


def _server_with_client(monkeypatch: pytest.MonkeyPatch, client: MagicMock):
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    return server


def test_delete_storage_access_key_forwards_inventory_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.kos.accessKeys.list.return_value = [
        AccessKeyListResponseItem.model_validate(
            {
                "access_key": "HYD-KEY-1",
                "region": "In-Hyderabad-1",
                "tier": "tier-2",
            }
        )
    ]
    client.kos.accessKeys.delete_access_keys.return_value = {"access_key_id": "HYD-KEY-1"}
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("delete_storage_access_key").fn(
        access_key_id="HYD-KEY-1",
        region="In-Hyderabad-1",
        confirm=True,
    )

    assert result.ok is True
    client.kos.accessKeys.list.assert_called_once_with()
    client.kos.accessKeys.delete_access_keys.assert_called_once_with(
        access_key_id="HYD-KEY-1",
        x_region_id="In-Hyderabad-1",
        extra_headers={"x-tier": "tier-2"},
    )


def test_delete_storage_access_key_blocks_region_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.kos.accessKeys.list.return_value = [
        {
            "access_key": "BLR-KEY-1",
            "region": "In-Bangalore-1",
            "tier": "tier-1",
        }
    ]
    server = _server_with_client(monkeypatch, client)

    with pytest.raises(ToolError, match="belongs to region 'In-Bangalore-1'"):
        server._tool_manager.get_tool("delete_storage_access_key").fn(
            access_key_id="BLR-KEY-1",
            region="In-Hyderabad-1",
            confirm=True,
        )

    client.kos.accessKeys.delete_access_keys.assert_not_called()


def test_delete_storage_access_key_blocks_missing_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.kos.accessKeys.list.return_value = [
        {
            "access_key": "HYD-KEY-1",
            "region": "In-Hyderabad-1",
        }
    ]
    server = _server_with_client(monkeypatch, client)

    with pytest.raises(ToolError, match="did not return a supported tier"):
        server._tool_manager.get_tool("delete_storage_access_key").fn(
            access_key_id="HYD-KEY-1",
            region="In-Hyderabad-1",
            confirm=True,
        )

    client.kos.accessKeys.delete_access_keys.assert_not_called()


def test_delete_storage_access_key_requires_confirmation_before_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    server = _server_with_client(monkeypatch, client)

    with pytest.raises(ToolError, match="confirm=true"):
        server._tool_manager.get_tool("delete_storage_access_key").fn(
            access_key_id="HYD-KEY-1",
            region="In-Hyderabad-1",
            confirm=False,
        )

    client.kos.accessKeys.list.assert_not_called()
    client.kos.accessKeys.delete_access_keys.assert_not_called()


def test_list_storage_access_keys_remains_account_wide(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.kos.accessKeys.list.return_value = []
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("list_storage_access_keys").fn()

    assert result.ok is True
    client.kos.accessKeys.list.assert_called_once_with()
