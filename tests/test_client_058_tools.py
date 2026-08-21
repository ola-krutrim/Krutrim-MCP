"""MCP coverage for krutrim-client 0.5.8 networking and KBS operations."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from krutrim_client import KrutrimClient
from krutrim_client import __version__ as client_version
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server
from tests.auth_tokens import TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN

VPC_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:vpc:"
    "00000000-0000-4000-8000-000000000001"
)
ATTACH_PORT_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:port:"
    "00000000-0000-4000-8000-000000000002"
)
DETACH_PORT_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:port:"
    "00000000-0000-4000-8000-000000000003"
)
FLOATING_IP_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:floatingIP:"
    "00000000-0000-4000-8000-000000000007"
)
SECURITY_GROUP_KRN = (
    "krn:krutrim-sg:In-Bangalore-1:customer-test:account-test:sg:"
    "00000000-0000-4000-8000-000000000004"
)
VOLUME_KRN = (
    "krn:kbs:In-Bangalore-1:customer-test:account-test:volume:"
    "00000000-0000-4000-8000-000000000005"
)
INSTANCE_KRN = (
    "krn:vm:In-Bangalore-1:customer-test:account-test:instance:"
    "00000000-0000-4000-8000-000000000006"
)


def _settings(**overrides: object) -> Settings:
    values = {
        "api_key": None,
        "base_url": "https://cloud.olakrutrim.com",
        "default_region": "In-Bangalore-1",
        "read_only": False,
        "log_level": "WARNING",
        "client_max_retries": 0,
        "tool_profile": "admin",
        "enable_sensitive_tools": True,
        "access_token": TEST_ACCESS_TOKEN,
        "refresh_token": TEST_REFRESH_TOKEN,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _server_with_client(monkeypatch: pytest.MonkeyPatch, client: MagicMock):
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    return server


def _configure_instance(client: MagicMock) -> None:
    client.highlvlvpc.retrieve_instance.return_value = {
        "krn": INSTANCE_KRN,
        "project_krn": VPC_KRN,
        "status": "ACTIVE",
    }


def test_required_client_058_surface_is_installed() -> None:
    assert tuple(int(part) for part in client_version.split(".")) >= (0, 5, 8)
    client = KrutrimClient(api_key="test", base_url="https://example.invalid")
    try:
        for method in (
            "list_floating_ips",
            "attach_floating_ip",
            "detach_floating_ip",
            "update_port_security_groups",
        ):
            assert hasattr(client.highlvlvpc, method)
        for method in ("list_volumes", "attach_volume", "detach_volume"):
            assert hasattr(client.kbs, method)
    finally:
        client.close()


def test_client_058_tools_have_explicit_safety_policies() -> None:
    server = create_server(_settings())
    expected = {
        "list_floating_ips": (True, False),
        "attach_volume": (False, False),
        "attach_floating_ip": (False, True),
        "detach_floating_ip": (False, True),
        "delete_floating_ip": (False, True),
        "detach_volume": (False, True),
        "update_port_security_groups": (False, True),
    }
    for name, (read_only, destructive) in expected.items():
        tool = server._tool_manager.get_tool(name)
        assert tool is not None
        assert tool.annotations.readOnlyHint is read_only
        assert tool.annotations.destructiveHint is destructive

    assert set(server._tool_manager.get_tool("list_floating_ips").parameters["required"]) == {
        "vpc_id",
        "region",
    }
    assert set(server._tool_manager.get_tool("attach_volume").parameters["required"]) == {
        "volume_id",
        "instance_id",
        "vpc_krn",
        "region",
        "confirm",
    }
    attach_floating_ip = server._tool_manager.get_tool("attach_floating_ip").parameters
    assert set(attach_floating_ip["required"]) == {
        "vpc_id",
        "attach_port",
        "detach_port",
        "region",
        "confirm",
    }
    assert "reservation-port KRN" in attach_floating_ip["properties"]["attach_port"][
        "description"
    ]
    assert "Destination VM port KRN" in attach_floating_ip["properties"]["detach_port"][
        "description"
    ]
    assert set(server._tool_manager.get_tool("delete_floating_ip").parameters["required"]) == {
        "vpc_id",
        "floating_ip_krn",
        "region",
        "confirm",
    }


def test_list_floating_ips_and_volumes_use_client_058_methods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.highlvlvpc.list_floating_ips.return_value = []
    client.kbs.list_volumes.return_value = []
    server = _server_with_client(monkeypatch, client)

    floating_result = server._tool_manager.get_tool("list_floating_ips").fn(
        vpc_id=VPC_KRN,
        region="In-Bangalore-1",
    )
    volume_result = server._tool_manager.get_tool("list_volumes").fn(
        vpc_krn=VPC_KRN,
        region="In-Bangalore-1",
    )

    assert floating_result.ok is True
    assert volume_result.ok is True
    client.highlvlvpc.list_floating_ips.assert_called_once_with(
        vpc_id=VPC_KRN,
        x_region="In-Bangalore-1",
    )
    client.kbs.list_volumes.assert_called_once_with(
        k_tenant_id=VPC_KRN,
        x_region="In-Bangalore-1",
    )


def test_attach_floating_ip_preflights_both_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.highlvlvpc.search_ports.return_value = [{"krn_id": DETACH_PORT_KRN}]
    client.highlvlvpc.list_floating_ips.return_value = [
        {"port_krn": ATTACH_PORT_KRN, "floating_ip_address": "203.0.113.10"}
    ]
    client.highlvlvpc.attach_floating_ip.return_value = {"message": "attached"}
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("attach_floating_ip").fn(
        vpc_id=VPC_KRN,
        attach_port=ATTACH_PORT_KRN,
        detach_port=DETACH_PORT_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    client.highlvlvpc.search_ports.assert_called_once_with(
        x_region="In-Bangalore-1",
        vpc_id=VPC_KRN,
        port_id=DETACH_PORT_KRN,
        page=1,
        size=100,
    )
    client.highlvlvpc.list_floating_ips.assert_called_once_with(
        vpc_id=VPC_KRN,
        x_region="In-Bangalore-1",
    )
    client.highlvlvpc.attach_floating_ip.assert_called_once_with(
        attach_port=ATTACH_PORT_KRN,
        detach_port=DETACH_PORT_KRN,
        x_region="In-Bangalore-1",
    )


def test_detach_floating_ip_requires_exact_inventory_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.highlvlvpc.list_floating_ips.return_value = [
        {"port_krn": DETACH_PORT_KRN, "floating_ip_address": "203.0.113.10"}
    ]
    client.highlvlvpc.detach_floating_ip.return_value = {"message": "detached"}
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("detach_floating_ip").fn(
        vpc_id=VPC_KRN,
        port_krn=DETACH_PORT_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    client.highlvlvpc.detach_floating_ip.assert_called_once_with(
        port_krn=DETACH_PORT_KRN,
        x_region="In-Bangalore-1",
    )


def test_delete_floating_ip_requires_exact_detached_inventory_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.highlvlvpc.list_floating_ips.return_value = [
        {
            "floating_ip_krn": FLOATING_IP_KRN,
            "floating_ip_address": "203.0.113.10",
            "port_krn": ATTACH_PORT_KRN,
            "vm_name": "unknown",
        }
    ]
    delete_api = MagicMock(return_value={"message": "deleted"})
    monkeypatch.setattr(
        "krutrim_mcp_server.tools.networking.ports.delete_floating_ip_api",
        delete_api,
    )
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("delete_floating_ip").fn(
        vpc_id=VPC_KRN,
        floating_ip_krn=FLOATING_IP_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    client.highlvlvpc.list_floating_ips.assert_called_once_with(
        vpc_id=VPC_KRN,
        x_region="In-Bangalore-1",
    )
    delete_api.assert_called_once_with(
        client,
        floating_ip_krn=FLOATING_IP_KRN,
        x_region="In-Bangalore-1",
    )


def test_delete_floating_ip_blocks_attached_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.highlvlvpc.list_floating_ips.return_value = [
        {
            "floating_ip_krn": FLOATING_IP_KRN,
            "port_krn": DETACH_PORT_KRN,
            "vm_name": "active-vm",
        }
    ]
    delete_api = MagicMock()
    monkeypatch.setattr(
        "krutrim_mcp_server.tools.networking.ports.delete_floating_ip_api",
        delete_api,
    )
    server = _server_with_client(monkeypatch, client)

    with pytest.raises(ToolError, match="detach it before deleting"):
        server._tool_manager.get_tool("delete_floating_ip").fn(
            vpc_id=VPC_KRN,
            floating_ip_krn=FLOATING_IP_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

    delete_api.assert_not_called()


def test_update_port_security_groups_preflights_exact_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.highlvlvpc.search_ports.return_value = {
        "ports": [{"port_id": ATTACH_PORT_KRN}]
    }
    client.securityGroup.list_by_vpc.return_value = {
        "items": [{"id": SECURITY_GROUP_KRN}],
        "total_count": 1,
    }
    client.highlvlvpc.update_port_security_groups.return_value = {
        "port": {"krn_id": ATTACH_PORT_KRN}
    }
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("update_port_security_groups").fn(
        vpc_id=VPC_KRN,
        port_krn=ATTACH_PORT_KRN,
        security_group_ids=[SECURITY_GROUP_KRN],
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    client.highlvlvpc.update_port_security_groups.assert_called_once_with(
        ATTACH_PORT_KRN,
        security_groups=[SECURITY_GROUP_KRN],
        x_region="In-Bangalore-1",
    )


def test_update_port_security_groups_accepts_client_result_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    client.highlvlvpc.search_ports.return_value = {
        "ports": [{"port_id": ATTACH_PORT_KRN}]
    }
    client.securityGroup.list_by_vpc.return_value = {
        "items": None,
        "result": [{"id": SECURITY_GROUP_KRN}],
        "pagination": {"totalCount": 1},
    }
    client.highlvlvpc.update_port_security_groups.return_value = {
        "port": {"krn_id": ATTACH_PORT_KRN}
    }
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("update_port_security_groups").fn(
        vpc_id=VPC_KRN,
        port_krn=ATTACH_PORT_KRN,
        security_group_ids=[SECURITY_GROUP_KRN],
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    client.highlvlvpc.update_port_security_groups.assert_called_once_with(
        ATTACH_PORT_KRN,
        security_groups=[SECURITY_GROUP_KRN],
        x_region="In-Bangalore-1",
    )


def test_attach_volume_preflights_vm_and_available_volume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    _configure_instance(client)
    client.kbs.retrieve_volume.return_value = {
        "id": VOLUME_KRN,
        "status": "available",
        "attachments": [],
    }
    client.kbs.attach_volume.return_value = {"message": "attach started"}
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("attach_volume").fn(
        volume_id=VOLUME_KRN,
        instance_id=INSTANCE_KRN,
        vpc_krn=VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    client.kbs.attach_volume.assert_called_once_with(
        VOLUME_KRN,
        instance_id=INSTANCE_KRN,
        k_tenant_id=VPC_KRN,
        x_region="In-Bangalore-1",
        mount_partition="/dev/vdz",
    )


def test_attach_volume_blocks_unverifiable_volume_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    _configure_instance(client)
    client.kbs.retrieve_volume.return_value = {
        "id": VOLUME_KRN,
        "attachments": [],
    }
    server = _server_with_client(monkeypatch, client)

    with pytest.raises(ToolError, match="verifiable attachment state"):
        server._tool_manager.get_tool("attach_volume").fn(
            volume_id=VOLUME_KRN,
            instance_id=INSTANCE_KRN,
            vpc_krn=VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

    client.kbs.attach_volume.assert_not_called()


def test_detach_volume_preflights_exact_attachment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MagicMock()
    _configure_instance(client)
    client.kbs.retrieve_volume.return_value = {
        "id": VOLUME_KRN,
        "status": "in-use",
        "attachments": [
            {
                "instance_id": INSTANCE_KRN,
                "remote_attachment_id": "attachment-1",
            }
        ],
    }
    client.kbs.detach_volume.return_value = {"message": "detach started"}
    server = _server_with_client(monkeypatch, client)

    result = server._tool_manager.get_tool("detach_volume").fn(
        volume_id=VOLUME_KRN,
        instance_id=INSTANCE_KRN,
        attachment_id="attachment-1",
        vpc_krn=VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    client.kbs.detach_volume.assert_called_once_with(
        VOLUME_KRN,
        instance_id=INSTANCE_KRN,
        attachment_id="attachment-1",
        k_tenant_id=VPC_KRN,
        x_region="In-Bangalore-1",
    )


@pytest.mark.parametrize(
    "tool_name,arguments",
    [
        (
            "attach_floating_ip",
            {
                "vpc_id": VPC_KRN,
                "attach_port": ATTACH_PORT_KRN,
                "detach_port": DETACH_PORT_KRN,
            },
        ),
        (
            "attach_volume",
            {
                "volume_id": VOLUME_KRN,
                "instance_id": INSTANCE_KRN,
                "vpc_krn": VPC_KRN,
            },
        ),
        (
            "delete_floating_ip",
            {
                "vpc_id": VPC_KRN,
                "floating_ip_krn": FLOATING_IP_KRN,
            },
        ),
        (
            "detach_volume",
            {
                "volume_id": VOLUME_KRN,
                "instance_id": INSTANCE_KRN,
                "attachment_id": "attachment-1",
                "vpc_krn": VPC_KRN,
            },
        ),
    ],
)
def test_client_058_mutations_require_confirmation_before_client(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    arguments: dict[str, object],
) -> None:
    client = MagicMock()
    server = _server_with_client(monkeypatch, client)

    with pytest.raises(ToolError, match="confirm=true"):
        server._tool_manager.get_tool(tool_name).fn(
            **arguments,
            region="In-Bangalore-1",
            confirm=False,
        )

    assert client.mock_calls == []
