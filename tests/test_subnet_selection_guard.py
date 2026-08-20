"""Regression tests for choosing a subnet KRN rather than a parent network KRN."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server
from krutrim_mcp_server.tools.compute import instances as instance_tools
from tests.auth_tokens import TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN

_VPC_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:vpc:"
    "00000000-0000-4000-8000-000000000001"
)
_NETWORK_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:network:"
    "00000000-0000-4000-8000-000000000002"
)
_SUBNET_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:subnet:"
    "00000000-0000-4000-8000-000000000003"
)
_COMPACT_NETWORK_KRN = (
    "krn:krutrim:network:In-Bangalore-1:customer-test:network/"
    "00000000-0000-4000-8000-000000000002"
)
_COMPACT_SUBNET_KRN = (
    "krn:krutrim:network:In-Bangalore-1:customer-test:subnet/"
    "00000000-0000-4000-8000-000000000003"
)


def _settings() -> Settings:
    return Settings(
        api_key=None,
        base_url="https://cloud.olakrutrim.com",
        default_region="",
        read_only=False,
        log_level="ERROR",
        client_max_retries=0,
        tool_profile="all",
        access_token=TEST_ACCESS_TOKEN,
        refresh_token=TEST_REFRESH_TOKEN,
    )


def _network_inventory(*, subnet_id: str = _SUBNET_KRN) -> list[dict[str, object]]:
    return [
        {
            "vpc_id": _VPC_KRN,
            "network_id": _NETWORK_KRN,
            "name": "example-network",
            "status": "ACTIVE",
            "subnets": [subnet_id],
        }
    ]


def _create_instance_args(*, subnet_id: str) -> dict[str, object]:
    return {
        "instance_name": "subnet-guard-vm",
        "instance_type": "CPU-2x-8GB",
        "vpc_id": _VPC_KRN,
        "subnet_id": subnet_id,
        "ssh_key_name": "test-key",
        "security_group_ids": ["security-group-1"],
        "image_krn": "image-1",
        "region": "In-Bangalore-1",
        "confirm": True,
    }


def _use_client(monkeypatch: pytest.MonkeyPatch, mock_client: MagicMock) -> None:
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)


def test_list_subnets_emits_selection_safe_subnet_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.search_networks.return_value = _network_inventory()
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)

    result = server._tool_manager.get_tool("list_subnets").fn(
        vpc_id=_VPC_KRN,
        region="In-Bangalore-1",
    )

    assert result.ok is True
    assert result.data == {
        "vpc_id": _VPC_KRN,
        "subnets": [
            {
                "subnet_id": _SUBNET_KRN,
                "parent_network_id": _NETWORK_KRN,
                "network_name": "example-network",
                "network_status": "ACTIVE",
            }
        ],
        "guidance": (
            "Pass a value from subnets[].subnet_id to create_instance or "
            "create_instance_template. parent_network_id is not a subnet and must not "
            "be supplied as subnet_id."
        ),
    }

    schema = server._tool_manager.get_tool("create_instance").parameters["properties"]
    assert "Never pass parent_network_id" in schema["subnet_id"]["description"]


@pytest.mark.parametrize("network_id", [_NETWORK_KRN, _COMPACT_NETWORK_KRN])
def test_create_instance_rejects_network_krn_before_client_access(
    monkeypatch: pytest.MonkeyPatch,
    network_id: str,
) -> None:
    get_client = MagicMock()
    from krutrim_mcp_server import client as client_mod

    server = create_server(_settings())
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match="network KRN, not a subnet KRN"):
        server._tool_manager.get_tool("create_instance").fn(
            **_create_instance_args(subnet_id=network_id)
        )

    get_client.assert_not_called()


@pytest.mark.parametrize("subnet_id", [_SUBNET_KRN, _COMPACT_SUBNET_KRN])
def test_create_instance_verifies_and_forwards_an_exact_subnet_krn(
    monkeypatch: pytest.MonkeyPatch,
    subnet_id: str,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.search_networks.return_value = _network_inventory(
        subnet_id=subnet_id
    )
    mock_client.highlvlvpc.create_instance.return_value = {"task_id": "task-1"}
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)
    monkeypatch.setattr(instance_tools, "validate_compute_flavor_name", MagicMock())

    result = server._tool_manager.get_tool("create_instance").fn(
        **_create_instance_args(subnet_id=subnet_id)
    )

    assert result.ok is True
    assert mock_client.highlvlvpc.search_networks.call_args.kwargs["vpc_id"] == _VPC_KRN
    assert mock_client.highlvlvpc.search_networks.call_args.kwargs["x_region"] == "In-Bangalore-1"
    assert mock_client.highlvlvpc.create_instance.call_args.kwargs["subnet_id"] == subnet_id


def test_create_instance_rejects_subnet_not_belonging_to_selected_vpc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.search_networks.return_value = _network_inventory()
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)
    foreign_subnet = _SUBNET_KRN.replace("000000000003", "000000000004")

    with pytest.raises(ToolError, match="not a subnet of the selected VPC"):
        server._tool_manager.get_tool("create_instance").fn(
            **_create_instance_args(subnet_id=foreign_subnet)
        )

    mock_client.highlvlvpc.create_instance.assert_not_called()


def test_create_instance_rejects_ambiguous_subnet_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    duplicate_owner = _network_inventory()
    duplicate_owner.append(
        {
            "vpc_id": _VPC_KRN,
            "network_id": _NETWORK_KRN.replace("000000000002", "000000000004"),
            "name": "another-network",
            "status": "ACTIVE",
            "subnets": [_SUBNET_KRN],
        }
    )
    mock_client.highlvlvpc.search_networks.return_value = duplicate_owner
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)

    with pytest.raises(ToolError, match="appears in multiple networks"):
        server._tool_manager.get_tool("create_instance").fn(
            **_create_instance_args(subnet_id=_SUBNET_KRN)
        )

    mock_client.highlvlvpc.create_instance.assert_not_called()


def test_create_instance_template_rejects_network_krn_before_client_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    get_client = MagicMock()
    from krutrim_mcp_server import client as client_mod

    server = create_server(_settings())
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match="network KRN, not a subnet KRN"):
        server._tool_manager.get_tool("create_instance_template").fn(
            template_name="subnet-guard-template",
            instance_type="CPU-2x-8GB",
            vpc_id=_VPC_KRN,
            subnet_id=_NETWORK_KRN,
            ssh_key_name="test-key",
            security_group_ids=["security-group-1"],
            image_krn="image-1",
            volume_name="test-volume",
            volume_size=50,
            volume_type="HNSS",
            region="In-Bangalore-1",
            confirm=True,
        )

    get_client.assert_not_called()
