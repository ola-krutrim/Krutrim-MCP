"""Region and tier routing tests for object-storage buckets."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
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


@pytest.mark.parametrize(
    ("region", "tier"),
    [
        ("In-Bangalore-1", "tier-1"),
        ("In-Hyderabad-1", "tier-2"),
    ],
)
def test_create_bucket_forwards_region_tier(
    monkeypatch: pytest.MonkeyPatch,
    region: str,
    tier: str,
) -> None:
    client = MagicMock()
    client.kos.buckets.create_bucket.return_value = {"name": "regional-bucket"}
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("create_bucket").fn(
        name="regional-bucket",
        region=region,
        confirm=True,
    )

    assert result.ok is True
    client.kos.buckets.create_bucket.assert_called_once_with(
        name="regional-bucket",
        region=region,
        x_region_id=region,
        anonymous_access=False,
        versioning=False,
        extra_headers={"x-tier": tier},
        extra_body={"tier": tier},
    )


def test_delete_bucket_forwards_inventory_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bucket_krn = "krn:kos:hyd-1:account:customer:bucket:bucket-id"
    client = MagicMock()
    client.get.return_value = {
        "items": [
            {
                "krnid": bucket_krn,
                "region": "In-Hyderabad-1",
                "tier": "tier-2",
            }
        ]
    }
    client.kos.buckets.delete_bucket.return_value = {"bucket_krn": bucket_krn}
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("delete_bucket").fn(
        bucket_krn=bucket_krn,
        region="In-Hyderabad-1",
        confirm=True,
    )

    assert result.ok is True
    client.get.assert_called_once_with("/kos/v1/buckets", cast_to=object)
    client.kos.buckets.delete_bucket.assert_called_once_with(
        bucket_krn,
        x_region_id="In-Hyderabad-1",
        extra_headers={"x-tier": "tier-2"},
    )


def test_delete_bucket_blocks_region_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bucket_krn = "krn:kos:colo-1:account:customer:bucket:bucket-id"
    client = MagicMock()
    client.get.return_value = [
        {
            "krnid": bucket_krn,
            "region": "In-Bangalore-1",
            "tier": "tier-1",
        }
    ]
    server = _server_with_client(monkeypatch, client)

    with pytest.raises(ToolError, match="belongs to region 'In-Bangalore-1'"):
        server._tool_manager.get_tool("delete_bucket").fn(
            bucket_krn=bucket_krn,
            region="In-Hyderabad-1",
            confirm=True,
        )

    client.kos.buckets.delete_bucket.assert_not_called()


def test_delete_bucket_blocks_missing_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bucket_krn = "krn:kos:hyd-1:account:customer:bucket:bucket-id"
    client = MagicMock()
    client.get.return_value = {
        "items": [
            {
                "krnid": bucket_krn,
                "region": "In-Hyderabad-1",
            }
        ]
    }
    server = _server_with_client(monkeypatch, client)

    with pytest.raises(ToolError, match="did not return a supported tier"):
        server._tool_manager.get_tool("delete_bucket").fn(
            bucket_krn=bucket_krn,
            region="In-Hyderabad-1",
            confirm=True,
        )

    client.kos.buckets.delete_bucket.assert_not_called()


def test_delete_bucket_requires_confirmation_before_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    server = _server_with_client(monkeypatch, client)

    with pytest.raises(ToolError, match="confirm=true"):
        server._tool_manager.get_tool("delete_bucket").fn(
            bucket_krn="krn:kos:hyd-1:account:customer:bucket:bucket-id",
            region="In-Hyderabad-1",
            confirm=False,
        )

    client.get.assert_not_called()
    client.kos.buckets.delete_bucket.assert_not_called()


def test_list_buckets_remains_account_wide(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.get.return_value = {"items": []}
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("list_buckets").fn()

    assert result.ok is True
    client.get.assert_called_once_with("/kos/v1/buckets", cast_to=object)
