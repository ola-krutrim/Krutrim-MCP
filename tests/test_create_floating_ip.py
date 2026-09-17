"""Tests for the create_floating_ip tool (issue #109).

The MCP surface previously exposed list/attach/detach/delete for floating
IPs but nothing that allocates one, so an account with zero floating IPs had
no path to a reachable VM. Allocation is implemented through the verified
backend contract: POST /v1/highlvlvpc/create_port with floating_ip=true
returns floating_ip_krn, floating_ip_address, and the reservation port_krn.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server

_ACCOUNT = "customer-test:account-test"
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
_MASKED_NETWORK_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:***:network:"
    "00000000-0000-4000-8000-000000000002"
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


def _args(**overrides: object) -> dict[str, object]:
    args: dict[str, object] = {
        "vpc_id": _VPC_KRN,
        "network_id": _NETWORK_KRN,
        "subnet_id": _SUBNET_KRN,
        "name": "agent-fip",
        "allow_public_ip": True,
        "region": "In-Bangalore-1",
        "confirm": True,
    }
    args.update(overrides)
    return args


def _prepared(monkeypatch: pytest.MonkeyPatch, mock_client: MagicMock):
    from krutrim_mcp_server import client as client_mod

    server = create_server(_settings())
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    return server


def test_create_floating_ip_reserves_via_port_with_floating_ip_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.create_port.return_value = {
        "floating_ip_address": "10.230.159.178",
        "floating_ip_krn": _VPC_KRN.replace(":vpc:", ":floatingIP:"),
        "message": "Port created successfully",
        "port_krn": _VPC_KRN.replace(":vpc:", ":port:"),
    }
    server = _prepared(monkeypatch, mock_client)

    result = server._tool_manager.get_tool("create_floating_ip").fn(**_args())

    assert result.ok is True
    call = mock_client.highlvlvpc.create_port.call_args
    assert call.kwargs["floating_ip"] is True
    assert call.kwargs["vpc_id"] == _VPC_KRN
    assert call.kwargs["network_id"] == _NETWORK_KRN
    assert call.kwargs["subnet_id"] == _SUBNET_KRN
    assert call.kwargs["name"] == "agent-fip"
    assert call.kwargs["x_region"] == "In-Bangalore-1"
    assert result.data["floating_ip_address"] == "10.230.159.178"


def test_create_floating_ip_requires_allow_public_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    server = _prepared(monkeypatch, mock_client)

    with pytest.raises(ToolError, match="allow_public_ip"):
        server._tool_manager.get_tool("create_floating_ip").fn(
            **_args(allow_public_ip=False)
        )

    mock_client.highlvlvpc.create_port.assert_not_called()


def test_create_floating_ip_rejects_masked_account_krns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Krutrim listings redact the account segment as ':***:'; the API rejects
    # masked KRNs, so the tool must fail with actionable guidance instead of
    # sending a doomed request.
    mock_client = MagicMock()
    server = _prepared(monkeypatch, mock_client)

    with pytest.raises(ToolError, match="masked account segment"):
        server._tool_manager.get_tool("create_floating_ip").fn(
            **_args(network_id=_MASKED_NETWORK_KRN)
        )

    mock_client.highlvlvpc.create_port.assert_not_called()


def test_create_floating_ip_rejects_resources_outside_the_vpc_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    server = _prepared(monkeypatch, mock_client)
    foreign_subnet = _SUBNET_KRN.replace("account-test", "other-account")

    with pytest.raises(ToolError, match="does not belong to the selected VPC"):
        server._tool_manager.get_tool("create_floating_ip").fn(
            **_args(subnet_id=foreign_subnet)
        )

    mock_client.highlvlvpc.create_port.assert_not_called()


def test_create_floating_ip_requires_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    server = _prepared(monkeypatch, mock_client)

    with pytest.raises(ToolError, match="confirm"):
        server._tool_manager.get_tool("create_floating_ip").fn(
            **_args(confirm=False)
        )

    mock_client.highlvlvpc.create_port.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [404, "read_timeout", 401, 403, 429, 500])
async def test_allocation_request_failure_warns_of_ambiguous_outcome_through_mcp(
    monkeypatch: pytest.MonkeyPatch, failure: int | str,
) -> None:
    from krutrim_mcp_server import client as client_mod

    configured = _settings()
    requests: list[httpx.Request] = []
    clients: list[KrutrimClient] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        # The backend may have allocated before the response fails. No live Cloud I/O.
        if failure == "read_timeout":
            raise httpx.ReadTimeout(f"reflected {configured.api_key}", request=request)
        return httpx.Response(int(failure), json={"message": f"reflected {configured.api_key}"})

    def factory(**kwargs: Any) -> KrutrimClient:
        assert kwargs["max_retries"] == 0
        sdk = KrutrimClient(
            http_client=httpx.Client(transport=httpx.MockTransport(handler)), **kwargs,
        )
        clients.append(sdk)
        return sdk

    monkeypatch.setattr(client_mod, "KrutrimClient", factory)
    server = create_server(configured)
    try:
        async with create_connected_server_and_client_session(server._mcp_server) as protocol:
            catalog = {tool.name: tool for tool in (await protocol.list_tools()).tools}
            for tool_name in ("list_floating_ips", "search_ports"):
                assert {"vpc_id", "region"} <= set(
                    catalog[tool_name].inputSchema["properties"]
                )
            result = await protocol.call_tool("create_floating_ip", _args())
        # No hidden retry, inventory request, automatic deletion, or success response.
        assert len(requests) == 1
        request = requests[0]
        assert request.method == "POST"
        assert request.url.path == "/v1/highlvlvpc/create_port"
        assert request.headers["x-region"] == "In-Bangalore-1"
        assert request.headers["Authorization"] == f"Bearer {configured.api_key}"
        assert json.loads(request.content) == {
            "floating_ip": True,
            "name": "agent-fip",
            "network_id": _NETWORK_KRN,
            "subnet_id": _SUBNET_KRN,
            "vpc_id": _VPC_KRN,
        }
        assert result.isError is True
        assert configured.api_key not in result.model_dump_json()
        message = " ".join(item.text for item in result.content if item.type == "text")
        assert ("APITimeoutError" if failure == "read_timeout" else str(failure)) in message
        assert "billable floating IP" in message
        assert "reservation port may" in message
        assert "Do NOT retry" in message
        assert "before any retry" in message
        assert "list_floating_ips" in message
        assert "search_ports" in message
        assert _VPC_KRN in message
        assert "In-Bangalore-1" in message
        assert "Retry after a short backoff" not in message
        if failure == 401:
            assert "Authentication failed (401)" in message
            assert "KRUTRIM_API_KEY" in message
        elif failure == 403:
            assert "Permission denied (403)" in message
    finally:
        for sdk in clients:
            sdk.close()
