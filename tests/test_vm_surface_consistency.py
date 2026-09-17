"""Tests for delete_subnet (issue ola-krutrim/Krutrim-MCP#3) and the VM tool
consistency fixes (issue ola-krutrim/Krutrim-MCP#5)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server

_VPC_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:vpc:"
    "00000000-0000-4000-8000-000000000001"
)
_SUBNET_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:subnet:"
    "00000000-0000-4000-8000-000000000003"
)


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "api_key": "test-api-key-for-offline-tests",
        "base_url": "https://cloud.olakrutrim.com",
        "default_region": "",
        "read_only": False,
        "log_level": "ERROR",
        "client_max_retries": 0,
        "tool_profile": "all",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _prepared(monkeypatch: pytest.MonkeyPatch, mock_client: MagicMock):
    from krutrim_mcp_server import client as client_mod

    server = create_server(_settings())
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    return server


class TestDeleteSubnet:
    def test_deletes_via_direct_api(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_client = MagicMock()
        response = MagicMock()
        response.json.return_value = {"success": "Successfully deleted the Subnet"}
        response.headers = {"content-type": "application/json"}
        mock_client.delete.return_value = response
        server = _prepared(monkeypatch, mock_client)

        result = server._tool_manager.get_tool("delete_subnet").fn(
            vpc_id=_VPC_KRN,
            subnet_id=_SUBNET_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

        assert result.ok is True
        call = mock_client.delete.call_args
        assert call.args[0] == "/v1/highlvlvpc/delete_subnet"
        params = call.kwargs["options"]["params"]
        assert params == {"subnet_id": _SUBNET_KRN, "vpc_id": _VPC_KRN}
        assert call.kwargs["options"]["headers"]["x-region"] == "In-Bangalore-1"

    def test_requires_confirmation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_client = MagicMock()
        server = _prepared(monkeypatch, mock_client)

        with pytest.raises(ToolError, match="confirm"):
            server._tool_manager.get_tool("delete_subnet").fn(
                vpc_id=_VPC_KRN,
                subnet_id=_SUBNET_KRN,
                region="In-Bangalore-1",
                confirm=False,
            )

        mock_client.delete.assert_not_called()

    def test_rejects_masked_account_krn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_client = MagicMock()
        server = _prepared(monkeypatch, mock_client)

        with pytest.raises(ToolError, match="masked account segment"):
            server._tool_manager.get_tool("delete_subnet").fn(
                vpc_id=_VPC_KRN,
                subnet_id=_SUBNET_KRN.replace(":account-test:", ":***:"),
                region="In-Bangalore-1",
                confirm=True,
            )

        mock_client.delete.assert_not_called()


class TestVmToolConsistency:
    def test_list_security_groups_accepts_vpc_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_client = MagicMock()
        mock_client.securityGroup.list_by_vpc.return_value = []
        server = _prepared(monkeypatch, mock_client)

        result = server._tool_manager.get_tool("list_security_groups").fn(
            vpc_id=_VPC_KRN, region="In-Bangalore-1"
        )

        assert result.ok is True
        call = mock_client.securityGroup.list_by_vpc.call_args
        assert call.kwargs["vpc_krn_identifier"] == _VPC_KRN

    def test_list_security_groups_still_accepts_legacy_vpc_krn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_client = MagicMock()
        mock_client.securityGroup.list_by_vpc.return_value = []
        server = _prepared(monkeypatch, mock_client)

        result = server._tool_manager.get_tool("list_security_groups").fn(
            vpc_krn=_VPC_KRN, region="In-Bangalore-1"
        )

        assert result.ok is True
        call = mock_client.securityGroup.list_by_vpc.call_args
        assert call.kwargs["vpc_krn_identifier"] == _VPC_KRN

    def test_list_security_groups_requires_some_vpc_identifier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_client = MagicMock()
        server = _prepared(monkeypatch, mock_client)

        with pytest.raises(ToolError, match="vpc_id is required"):
            server._tool_manager.get_tool("list_security_groups").fn(
                region="In-Bangalore-1"
            )

        mock_client.securityGroup.list_by_vpc.assert_not_called()

    def test_describe_instance_parses_ip_addresses_json_string(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        embedded = [
            {
                "mac": "fa:16:3e:78:c1:72",
                "network": "abc-test-network",
                "ip": "10.0.1.254",
                "type": "fixed",
            }
        ]
        mock_client = MagicMock()
        mock_client.highlvlvpc.retrieve_instance.return_value = {
            "instance_name": "vmlab-1",
            "ip_addresses": json.dumps(embedded),
        }
        server = _prepared(monkeypatch, mock_client)

        result = server._tool_manager.get_tool("describe_instance").fn(
            instance_krn=_VPC_KRN.replace(":vpc:", ":instance:"),
            region="In-Bangalore-1",
        )

        assert result.ok is True
        assert result.data["ip_addresses"] == embedded

    def test_describe_instance_leaves_unparseable_ip_addresses_alone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_client = MagicMock()
        mock_client.highlvlvpc.retrieve_instance.return_value = {
            "instance_name": "vmlab-1",
            "ip_addresses": "not-json",
        }
        server = _prepared(monkeypatch, mock_client)

        result = server._tool_manager.get_tool("describe_instance").fn(
            instance_krn=_VPC_KRN.replace(":vpc:", ":instance:"),
            region="In-Bangalore-1",
        )

        assert result.ok is True
        assert result.data["ip_addresses"] == "not-json"

    def test_list_ssh_keys_documents_where_customer_id_comes_from(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = _prepared(monkeypatch, MagicMock())
        tool = server._tool_manager.get_tool("list_ssh_keys")
        assert "account UUID" in (tool.description or "")
