"""Unit tests for MCP server tool registration and meta tools."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session

from krutrim_mcp_server import __version__
from krutrim_mcp_server.client import KrutrimCloudSession
from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.profiles import (
    ADDITIVE_TOOLS,
    DESTRUCTIVE_TOOLS,
    READ_ONLY_TOOLS,
    UNAVAILABLE_TOOLS,
)
from krutrim_mcp_server.server import create_server
from krutrim_mcp_server.tools.networking.rules import SecurityGroupRuleSpec


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = dict(
        api_key="test-api-key-for-offline-tests",
        base_url="https://cloud.olakrutrim.com",
        default_region="In-Bangalore-1",
        read_only=False,
        log_level="WARNING",
        client_max_retries=0,
        tool_profile="admin",
        enable_sensitive_tools=True,
    )
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch):
    return create_server(_settings())


def test_tools_registered(server) -> None:
    tools = server._tool_manager.list_tools()
    names = {t.name for t in tools}
    assert names == (READ_ONLY_TOOLS | ADDITIVE_TOOLS | DESTRUCTIVE_TOOLS) - UNAVAILABLE_TOOLS
    assert len(names) == 159


def test_default_catalog_exposes_all_supported_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    srv = create_server(_settings(tool_profile="core-readonly", enable_sensitive_tools=False))
    tools = srv._tool_manager.list_tools()
    assert len(tools) == 159
    assert srv._tool_manager.get_tool("list_compute_flavors") is not None
    assert srv._tool_manager.get_tool("list_gpu_compute_flavors") is not None
    assert srv._tool_manager.get_tool("list_kpod_flavors") is not None
    assert srv._tool_manager.get_tool("list_kpod_templates") is not None
    assert srv._tool_manager.get_tool("create_vpc") is not None
    assert srv._tool_manager.get_tool("create_kpod") is not None
    assert srv._tool_manager.get_tool("create_storage_access_key") is not None
    assert srv._tool_manager.get_tool("get_kks_kubeconfig") is not None


def test_dns_catalog_matches_official_krutrim_client_examples(server) -> None:
    dns_names = {
        tool.name for tool in server._tool_manager.list_tools() if "dns" in tool.name
    }
    assert dns_names == {
        "add_dns_zone_vpc",
        "create_dns_record",
        "create_dns_zone",
        "delete_dns_record",
        "delete_dns_zone",
        "get_dns_zone",
        "list_dns_records",
        "list_dns_zones",
        "remove_dns_zone_vpc",
        "update_dns_record",
    }


def test_certificate_tools_are_not_registered_on_main(server) -> None:
    removed_names = {
        "add_certificate_tags",
        "delete_certificate",
        "describe_certificate",
        "get_certificate_tag_value",
        "get_expiring_certificates",
        "list_certificates",
    }
    registered_names = {tool.name for tool in server._tool_manager.list_tools()}
    assert removed_names.isdisjoint(registered_names)


def test_load_balancer_tools_are_not_registered_on_main(server) -> None:
    removed_names = {
        "create_load_balancer",
        "create_target_group",
        "delete_load_balancer",
        "delete_target_group",
        "describe_load_balancer",
        "get_detailed_target_groups",
        "get_load_balancer_payload",
        "get_load_balancer_task_status",
        "list_load_balancers",
        "list_target_group_names",
        "list_target_groups",
        "update_load_balancer",
        "update_target_group",
    }
    registered_names = {tool.name for tool in server._tool_manager.list_tools()}
    assert removed_names.isdisjoint(registered_names)


def test_region_scoped_tools_require_region_selection(server) -> None:
    tool = server._tool_manager.get_tool("create_vpc")
    parameters = tool.parameters

    assert "region" in parameters["required"]
    assert "confirm" in parameters["required"]
    assert "subnet_cidr" in parameters["required"]
    assert set(parameters["properties"]) == {
        "name",
        "subnet_cidr",
        "region",
        "confirm",
    }
    assert parameters["properties"]["name"]["minLength"] == 1
    assert parameters["properties"]["region"]["enum"] == [
        "In-Bangalore-1",
        "In-Hyderabad-1",
    ]


def test_ping_and_list_regions(server) -> None:
    ping = server._tool_manager.get_tool("krutrim_ping")
    payload = ping.fn().model_dump()
    assert payload["ok"] is True
    assert payload["data"]["server"] == "krutrim-mcp-server"
    assert "version" in payload["data"]

    regions = server._tool_manager.get_tool("list_regions")
    data = regions.fn().model_dump()
    assert data["ok"] is True
    assert "In-Bangalore-1" in data["data"]["regions"]


def test_delete_requires_confirm(server) -> None:
    tool = server._tool_manager.get_tool("delete_vpc")
    with pytest.raises(ToolError, match="confirm=true"):
        tool.fn(vpc_id="vpc-123", confirm=False)


def test_create_requires_confirm(server) -> None:
    tool = server._tool_manager.get_tool("create_vpc")
    with pytest.raises(ToolError, match="confirm=true"):
        tool.fn(
            name="vpc-123",
            subnet_cidr="10.0.1.0/24",
            region="In-Bangalore-1",
            confirm=False,
        )


def test_create_vpc_uses_no_security_group_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    response = MagicMock()
    response.content = b'{"task_id":"task-1"}'
    response.status_code = 202
    response.json.return_value = {"task_id": "task-1"}
    mock_client.post.return_value = response
    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    tool = srv._tool_manager.get_tool("create_vpc")
    result = tool.fn(
        name="private-vpc",
        subnet_cidr="10.0.1.0/24",
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    args, kwargs = mock_client.post.call_args
    assert args == ("/v1/highlvlvpc/create_vpc_async",)
    assert set(kwargs["body"]) == {"network", "subnet", "vpc"}
    assert kwargs["body"]["subnet"] == {
        "name": "private-vpc-subnet",
        "cidr": "10.0.1.0/24",
        "description": "Default-subnet-for-private-vpc",
        "gateway_ip": "10.0.1.1",
        "ip_version": "4",
        "ingress": True,
        "egress": True,
    }
    assert kwargs["options"] == {"headers": {"x-region": "In-Bangalore-1"}}
    assert not {"security_group", "security_group_rule"} & kwargs["body"].keys()
    assert mock_client.securityGroup.mock_calls == []


@pytest.mark.parametrize(
    ("subnet_cidr", "error"),
    [
        ("2001:db8::/64", "supports IPv4 CIDRs only"),
        ("10.0.1.0/31", "usable host and gateway"),
    ],
)
def test_create_vpc_rejects_invalid_subnet_before_http(
    monkeypatch: pytest.MonkeyPatch,
    subnet_cidr: str,
    error: str,
) -> None:
    mock_client = MagicMock()
    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    tool = srv._tool_manager.get_tool("create_vpc")
    with pytest.raises(ToolError, match=error):
        tool.fn(
            name="safe-vpc",
            subnet_cidr=subnet_cidr,
            region="In-Bangalore-1",
            confirm=True,
        )
    mock_client.post.assert_not_called()


def test_create_vpc_rejects_blank_name_before_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    tool = srv._tool_manager.get_tool("create_vpc")
    with pytest.raises(ToolError, match="name cannot be blank"):
        tool.fn(
            name="   ",
            subnet_cidr="10.0.1.0/24",
            region="In-Bangalore-1",
            confirm=True,
        )
    mock_client.post.assert_not_called()


def test_delete_vpc_calls_client(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_client = MagicMock()

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    vpc_id = (
        "krn:vpc:In-Bangalore-1:7655600597:5134dc8b-54f6-4c7c-b468-4f582076c173:"
        "vpc:3256fcb1-f52e-407f-8eb2-188dcaed8088"
    )
    tool = srv._tool_manager.get_tool("delete_vpc")
    result = tool.fn(vpc_id=vpc_id, confirm=True, region="In-Bangalore-1")
    assert result.ok is True
    mock_client.highlvlvpc.delete_vpc.assert_called_once_with(
        vpc_id=vpc_id,
        x_region="In-Bangalore-1",
    )


def test_delete_failed_instance_passes_detail_task_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.retrieve_instance.return_value = {
        "krn": "krn:vm:In-Bangalore-1:test:instance:vm-1",
        "status": "ERROR",
        "task_id": "failed-create-task-1",
    }
    response = MagicMock()
    response.content = b'{"message":"accepted","task_id":"delete-task-1"}'
    response.status_code = 200
    response.json.return_value = {"message": "accepted", "task_id": "delete-task-1"}
    mock_client.delete.return_value = response

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    instance_krn = "krn:vm:In-Bangalore-1:test:instance:vm-1"
    tool = srv._tool_manager.get_tool("delete_instance")
    result = tool.fn(
        instance_krn=instance_krn,
        delete_volume=True,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.highlvlvpc.retrieve_instance.assert_called_once_with(
        krn=instance_krn,
        x_region="In-Bangalore-1",
    )
    args, kwargs = mock_client.delete.call_args
    assert args == ("/vm/v1/delete_instance_async",)
    assert kwargs["options"] == {
        "headers": {"x-region": "In-Bangalore-1"},
        "params": {
            "instanceKrn": instance_krn,
            "deleteVolume": True,
            "task_id": "failed-create-task-1",
        },
        "max_retries": 0,
    }


def test_delete_task_only_failed_instance_skips_detail_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    response = MagicMock()
    response.content = b'{"message":"accepted","task_id":"delete-task-2"}'
    response.status_code = 200
    response.json.return_value = {"message": "accepted", "task_id": "delete-task-2"}
    mock_client.delete.return_value = response

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("delete_instance")
    result = tool.fn(
        instance_krn="",
        failed_task_id="failed-create-task-2",
        delete_volume=True,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.highlvlvpc.retrieve_instance.assert_not_called()
    args, kwargs = mock_client.delete.call_args
    assert args == ("/vm/v1/delete_instance_async",)
    assert kwargs["options"] == {
        "headers": {"x-region": "In-Bangalore-1"},
        "params": {
            "deleteVolume": True,
            "task_id": "failed-create-task-2",
        },
        "max_retries": 0,
    }


def test_read_only_blocks_create(monkeypatch: pytest.MonkeyPatch) -> None:
    srv = create_server(_settings(read_only=True))
    tool = srv._tool_manager.get_tool("create_bucket")
    with pytest.raises(ToolError, match="READ_ONLY"):
        tool.fn(name="demo")


def test_list_vpcs_calls_client(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.list_vpcs.return_value = {
        "vpcs": [
            {"id": "v1", "operating_status": "success"},
            {"id": "v2", "status": "ACTIVE"},
            {"id": "v3", "operating_status": "deleted"},
            {"id": "v4", "status": "BUILD"},
        ]
    }

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("list_vpcs")
    result = tool.fn(region="In-Bangalore-1")
    assert result.ok is True
    assert result.data["vpcs"] == [
        {"id": "v1", "operating_status": "success"},
        {"id": "v2", "status": "ACTIVE"},
        {"id": "v3", "operating_status": "deleted"},
        {"id": "v4", "status": "BUILD"},
    ]
    mock_client.highlvlvpc.list_vpcs.assert_called_once()
    kwargs = mock_client.highlvlvpc.list_vpcs.call_args.kwargs
    assert kwargs["x_region"] == "In-Bangalore-1"


def test_list_vpcs_filters_active_rows_to_selected_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.list_vpcs.return_value = [
        {
            "operating_status": "ACTIVE",
            "vpcId": "krn:vpc:In-Bangalore-1:acct:cust:vpc:blr-active",
            "vpcName": "blr-active",
        },
        {
            "operating_status": "ACTIVE",
            "vpcId": "krn:vpc:In-Hyderabad-1:acct:cust:vpc:hyd-active",
            "vpcName": "hyd-active",
        },
        {
            "operating_status": "Not Found",
            "vpcId": "krn:vpc:In-Bangalore-1:acct:cust:vpc:blr-not-found",
            "vpcName": "blr-not-found",
        },
    ]

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("list_vpcs")
    result = tool.fn(region="In-Bangalore-1", include_inactive=False)

    assert result.ok is True
    assert result.data == [
        {
            "operating_status": "ACTIVE",
            "vpcId": "krn:vpc:In-Bangalore-1:acct:cust:vpc:blr-active",
            "vpcName": "blr-active",
        }
    ]


def test_search_vpcs_passes_region_header(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.search_vpcs.return_value = []

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("search_vpcs")
    result = tool.fn(region="In-Hyderabad-1", status="ACTIVE", page=1, size=10)

    assert result.ok is True
    mock_client.highlvlvpc.search_vpcs.assert_called_once_with(
        extra_headers={"x-region": "In-Hyderabad-1"},
        status="ACTIVE",
        page=1,
        size=10,
    )


def test_create_security_group_rule_calls_client(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-1"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_security_group_rule")
    result = tool.fn(
        vpc_id="vpc-1",
        direction="ingress",
        ethertype="ipv4",
        protocol="tcp",
        port_min=443,
        port_max=443,
        remote_ip_prefix="0.0.0.0/0",
        allow_public_ingress=True,
        region="In-Bangalore-1",
        confirm=True,
    )
    assert result.ok is True
    mock_client.securityGroup.create_rule.assert_called_once_with(
        direction="ingress",
        ethertypes="ipv4",
        port_max_range=443,
        port_min_range=443,
        protocol="tcp",
        remote_ip_prefix="0.0.0.0/0",
        vpcid="vpc-1",
        x_region="In-Bangalore-1",
    )


def test_create_security_group_rule_rejects_legacy_any_protocol(server) -> None:
    tool = server._tool_manager.get_tool("create_security_group_rule")

    with pytest.raises(ToolError, match="protocol must be one of: tcp, udp, icmp, all"):
        tool.fn(
            vpc_id="vpc-1",
            direction="ingress",
            ethertype="ipv4",
            protocol="any",
            port_min=1,
            port_max=65535,
            remote_ip_prefix="203.0.113.10/32",
            region="In-Hyderabad-1",
            confirm=True,
        )


def test_create_security_group_rule_requires_ports_for_specific_protocol(server) -> None:
    tool = server._tool_manager.get_tool("create_security_group_rule")

    with pytest.raises(
        ToolError,
        match="port_min and port_max are required unless protocol is 'all' or 'icmp'",
    ):
        tool.fn(
            vpc_id="vpc-1",
            direction="ingress",
            ethertype="ipv4",
            protocol="tcp",
            remote_ip_prefix="203.0.113.10/32",
            region="In-Hyderabad-1",
            confirm=True,
        )


def test_create_security_group_rule_maps_all_to_api_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-all"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_security_group_rule")
    result = tool.fn(
        vpc_id="vpc-1",
        direction="ingress",
        ethertype="ipv4",
        protocol="all",
        remote_ip_prefix="203.0.113.10/32",
        region="In-Hyderabad-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.securityGroup.create_rule.assert_called_once_with(
        direction="ingress",
        ethertypes="ipv4",
        port_max_range=65535,
        port_min_range=1,
        protocol="all",
        remote_ip_prefix="203.0.113.10/32",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )


def test_create_security_group_rule_icmp_without_ports_maps_to_api_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-icmp"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_security_group_rule")
    result = tool.fn(
        vpc_id="vpc-1",
        direction="ingress",
        ethertype="ipv4",
        protocol="icmp",
        remote_ip_prefix="203.0.113.10/32",
        region="In-Hyderabad-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.securityGroup.create_rule.assert_called_once_with(
        direction="ingress",
        ethertypes="ipv4",
        port_max_range=65535,
        port_min_range=1,
        protocol="icmp",
        remote_ip_prefix="203.0.113.10/32",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )


def test_create_security_group_rule_icmp_with_explicit_ports_passes_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-icmp-typed"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_security_group_rule")
    result = tool.fn(
        vpc_id="vpc-1",
        direction="ingress",
        ethertype="ipv4",
        protocol="icmp",
        port_min=8,
        port_max=8,
        remote_ip_prefix="203.0.113.10/32",
        region="In-Hyderabad-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.securityGroup.create_rule.assert_called_once_with(
        direction="ingress",
        ethertypes="ipv4",
        port_max_range=8,
        port_min_range=8,
        protocol="icmp",
        remote_ip_prefix="203.0.113.10/32",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )


def test_create_security_group_rule_tcp_still_requires_ports(server) -> None:
    tool = server._tool_manager.get_tool("create_security_group_rule")

    with pytest.raises(
        ToolError,
        match="port_min and port_max are required",
    ):
        tool.fn(
            vpc_id="vpc-1",
            direction="ingress",
            ethertype="ipv4",
            protocol="udp",
            remote_ip_prefix="203.0.113.10/32",
            region="In-Hyderabad-1",
            confirm=True,
        )


def test_create_security_group_without_rule_only_creates_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_security_group.return_value = {"id": "sg-1"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_security_group")
    result = tool.fn(
        name="web-sg",
        description="Web security group",
        vpc_id="vpc-1",
        region="In-Hyderabad-1",
        confirm=True,
    )

    assert result.ok is True
    assert result.data == {"id": "sg-1"}
    mock_client.securityGroup.create_security_group.assert_called_once_with(
        name="web-sg",
        description="Web security group",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )
    mock_client.securityGroup.create_rule.assert_not_called()
    mock_client.securityGroup.attach_rule.assert_not_called()


def test_create_security_group_with_rule_requires_explicit_user_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_security_group")
    with pytest.raises(ToolError, match="rule_requested_by_user=true"):
        tool.fn(
            name="web-sg",
            description="Web security group",
            vpc_id="vpc-1",
            rule=SecurityGroupRuleSpec(
                direction="ingress",
                ethertype="ipv4",
                protocol="tcp",
                port_min=443,
                port_max=443,
                remote_ip_prefix="203.0.113.10/32",
            ),
            region="In-Hyderabad-1",
            confirm=True,
        )

    mock_client.securityGroup.create_security_group.assert_not_called()


def test_create_security_group_with_rule_creates_and_attaches_in_one_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_security_group.return_value = {"id": "sg-1"}
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-1"}
    mock_client.securityGroup.attach_rule.return_value = {"status": "success"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_security_group")
    result = tool.fn(
        name="web-sg",
        description="Web security group",
        vpc_id="vpc-1",
        rule=SecurityGroupRuleSpec(
            direction="ingress",
            ethertype="ipv4",
            protocol="tcp",
            port_min=443,
            port_max=443,
            remote_ip_prefix="203.0.113.10/32",
        ),
        rule_requested_by_user=True,
        region="In-Hyderabad-1",
        confirm=True,
    )

    assert result.ok is True
    assert result.data["security_group_id"] == "sg-1"
    assert result.data["created_rule"] == {"id": "rule-1"}
    mock_client.securityGroup.create_rule.assert_called_once_with(
        direction="ingress",
        ethertypes="ipv4",
        port_max_range=443,
        port_min_range=443,
        protocol="tcp",
        remote_ip_prefix="203.0.113.10/32",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )
    mock_client.securityGroup.attach_rule.assert_called_once_with(
        ruleid="rule-1",
        securityid="sg-1",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )


def test_create_security_group_with_all_protocol_maps_api_port_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_security_group.return_value = {"id": "sg-1"}
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-all"}
    mock_client.securityGroup.attach_rule.return_value = {"status": "success"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_security_group")
    result = tool.fn(
        name="public-sg",
        description="Explicitly public security group",
        vpc_id="vpc-1",
        rule=SecurityGroupRuleSpec(
            direction="ingress",
            ethertype="ipv4",
            protocol="all",
            remote_ip_prefix="0.0.0.0/0",
        ),
        rule_requested_by_user=True,
        allow_public_ingress=True,
        region="In-Hyderabad-1",
        confirm=True,
    )

    assert result.ok is True
    assert result.data["requested_rule"]["protocol"] == "all"
    assert result.data["requested_rule"]["port_min"] == 1
    assert result.data["requested_rule"]["port_max"] == 65535
    mock_client.securityGroup.create_rule.assert_called_once_with(
        direction="ingress",
        ethertypes="ipv4",
        port_max_range=65535,
        port_min_range=1,
        protocol="all",
        remote_ip_prefix="0.0.0.0/0",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )
    mock_client.securityGroup.attach_rule.assert_called_once_with(
        ruleid="rule-all",
        securityid="sg-1",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )


def test_create_security_group_with_rule_rolls_back_group_and_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_security_group.return_value = {"id": "sg-1"}
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-1"}
    mock_client.securityGroup.attach_rule.side_effect = RuntimeError("attach failed")

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_security_group")
    with pytest.raises(ToolError, match="security group and rule were rolled back"):
        tool.fn(
            name="web-sg",
            description="Web security group",
            vpc_id="vpc-1",
            rule=SecurityGroupRuleSpec(
                direction="ingress",
                ethertype="ipv4",
                protocol="tcp",
                port_min=443,
                port_max=443,
                remote_ip_prefix="203.0.113.10/32",
            ),
            rule_requested_by_user=True,
            region="In-Hyderabad-1",
            confirm=True,
        )

    mock_client.securityGroup.delete_rule.assert_called_once_with(
        "rule-1", x_region="In-Hyderabad-1"
    )
    mock_client.securityGroup.delete_security_group.assert_called_once_with(
        "sg-1", x_region="In-Hyderabad-1"
    )


def test_create_and_attach_security_group_rule_calls_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-1"}
    mock_client.securityGroup.attach_rule.return_value = {"status": "success"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_and_attach_security_group_rule")
    result = tool.fn(
        security_group_id="sg-1",
        vpc_id="vpc-1",
        direction="ingress",
        ethertype="ipv4",
        protocol="tcp",
        port_min=22,
        port_max=22,
        remote_ip_prefix="203.0.113.10/32",
        region="In-Hyderabad-1",
        confirm=True,
    )
    assert result.ok is True
    mock_client.securityGroup.create_rule.assert_called_once()
    mock_client.securityGroup.attach_rule.assert_called_once_with(
        ruleid="rule-1",
        securityid="sg-1",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )


def test_create_and_attach_security_group_rule_maps_all_to_api_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-all"}
    mock_client.securityGroup.attach_rule.return_value = {"status": "success"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_and_attach_security_group_rule")
    result = tool.fn(
        security_group_id="sg-1",
        vpc_id="vpc-1",
        direction="ingress",
        ethertype="ipv4",
        protocol="all",
        port_min=80,
        port_max=80,
        remote_ip_prefix="203.0.113.10/32",
        region="In-Hyderabad-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.securityGroup.create_rule.assert_called_once_with(
        direction="ingress",
        ethertypes="ipv4",
        port_max_range=65535,
        port_min_range=1,
        protocol="all",
        remote_ip_prefix="203.0.113.10/32",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )
    mock_client.securityGroup.attach_rule.assert_called_once_with(
        ruleid="rule-all",
        securityid="sg-1",
        vpcid="vpc-1",
        x_region="In-Hyderabad-1",
    )


def test_create_and_attach_security_group_rule_accepts_nested_rule_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_rule.return_value = {
        "message": "Security group rule created successfully",
        "result": {"krn": "krn:krutrim-sgr:test:sgr:rule-1"},
    }
    mock_client.securityGroup.attach_rule.return_value = {"status": "success"}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("create_and_attach_security_group_rule")
    result = tool.fn(
        security_group_id="sg-1",
        vpc_id="vpc-1",
        direction="ingress",
        ethertype="ipv4",
        protocol="tcp",
        port_min=1,
        port_max=65535,
        remote_ip_prefix="203.0.113.10/32",
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.securityGroup.attach_rule.assert_called_once_with(
        ruleid="krn:krutrim-sgr:test:sgr:rule-1",
        securityid="sg-1",
        vpcid="vpc-1",
        x_region="In-Bangalore-1",
    )


def test_delete_security_group_rule_requires_confirm(server) -> None:
    tool = server._tool_manager.get_tool("delete_security_group_rule")
    with pytest.raises(ToolError, match="confirm=true"):
        tool.fn(rule_id="rule-1", confirm=False)


def test_plan_delete_is_explicitly_preview_only(server) -> None:
    tool = server._tool_manager.get_tool("plan_delete")
    result = tool.fn(
        resource_type="vpc",
        resource_id="vpc-9",
        region="In-Bangalore-1",
    )
    assert result.ok is True
    assert result.data["preview_only"] is True
    assert result.data["dependency_checked"] is False
    assert result.data["resource_id"] == "vpc-9"


def test_list_kks_clusters_calls_client(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_client = MagicMock()
    raw_list = mock_client.kks.clusters.with_raw_response.list
    raw_list.return_value.json.return_value = {"clusters": []}

    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    tool = srv._tool_manager.get_tool("list_kks_clusters")
    result = tool.fn()
    assert result.ok is True
    assert result.data == {"clusters": []}
    raw_list.assert_called_once_with()


@pytest.mark.asyncio
async def test_protocol_uses_structured_success_and_real_tool_errors(server) -> None:
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        initialized = await session.initialize()
        assert initialized.serverInfo.version == __version__
        success = await session.call_tool("krutrim_ping", {})
        assert success.isError is False
        assert success.structuredContent["ok"] is True
        assert success.structuredContent["data"]["server"] == "krutrim-mcp-server"

        failure = await session.call_tool(
            "delete_vpc",
            {"vpc_id": "vpc-123", "region": "In-Bangalore-1", "confirm": False},
        )
        assert failure.isError is True
        assert failure.structuredContent is None
        assert "confirm=true" in failure.content[0].text


def test_every_tool_has_structured_schema_and_annotations(server) -> None:
    for tool in server._tool_manager.list_tools():
        assert tool.output_schema["type"] == "object"
        assert tool.output_schema["properties"]["data"].get("type") != "string"
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint == (tool.name in READ_ONLY_TOOLS)
        assert tool.annotations.destructiveHint == (tool.name in DESTRUCTIVE_TOOLS)


def test_client_disables_sdk_retries_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from krutrim_mcp_server import client as client_mod

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(client_mod, "KrutrimClient", FakeClient)
    monkeypatch.setattr(client_mod, "_patch_client_compatibility", lambda client: None)

    session = KrutrimCloudSession(_settings(client_max_retries=0))
    session._build_client("test-key")

    assert captured["max_retries"] == 0
    assert captured["timeout"] == 30.0
