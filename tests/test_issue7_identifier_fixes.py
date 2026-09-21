"""Regression tests for issue #7-adjacent fixes found while validating #110.

1. delete_ssh_key must accept the `uuid` field (the only identifier the
   backend's delete endpoint accepts) and extract the UUID from full or
   masked key KRNs, because the API never populates `id`.
2. Security-group rule mutation tools must reject masked ':***:' KRNs with
   an actionable error instead of forwarding them to the API, which fails
   with an uninformative 400/404.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server
from krutrim_mcp_server.tools.compute.ssh_keys import _resolve_ssh_key_uuid

_UUID = "3ca8a2aa-c449-46c4-b0f0-e845bfb55e5a"
_MASKED_KEY_KRN = f"krn:krutrim-ssh:In-Bangalore-1:9167252691:***:sshkey:{_UUID}"
_FULL_KEY_KRN = (
    "krn:krutrim-ssh:In-Bangalore-1:9167252691:"
    f"3bb55dc4-56ab-4f51-8412-d01e30ef205e:sshkey:{_UUID}"
)
_MASKED_RULE_KRN = (
    "krn:krutrim-sgr:In-Bangalore-1:9167252691:***:sgr:"
    "8cc89c43-95ff-4afb-b557-089589b8d346"
)
_FULL_SG_KRN = (
    "krn:krutrim-sg:In-Bangalore-1:9167252691:"
    "3bb55dc4-56ab-4f51-8412-d01e30ef205e:sg:69818c11-9693-4c0c-b66b-12c22ae711a1"
)
_FULL_VPC_KRN = (
    "krn:vpc:In-Bangalore-1:9167252691:"
    "3bb55dc4-56ab-4f51-8412-d01e30ef205e:vpc:5d146d79-a800-462d-8f1e-f02859242ffa"
)


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


@pytest.fixture
def server():
    return create_server(_settings())


@pytest.mark.parametrize(
    "value,expected",
    [
        (_UUID, _UUID),
        (_FULL_KEY_KRN, _UUID),
        (_MASKED_KEY_KRN, _UUID),
        (f"  {_UUID}  ", _UUID),
    ],
)
def test_resolve_ssh_key_uuid_accepts_uuid_and_krn(value: str, expected: str) -> None:
    assert _resolve_ssh_key_uuid(value) == expected


@pytest.mark.parametrize("value", ["", "   "])
def test_resolve_ssh_key_uuid_rejects_empty(value: str) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        _resolve_ssh_key_uuid(value)


def test_delete_ssh_key_sends_uuid_extracted_from_masked_krn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    result = srv._tool_manager.get_tool("delete_ssh_key").fn(
        ssh_key_id=_MASKED_KEY_KRN,
        customer_id="cust-1",
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    assert result.data == {"deleted": True, "ssh_key_id": _UUID}
    mock_client.sshkey.delete_sshkey.assert_called_once_with(
        _UUID, x_region="In-Bangalore-1", customer_id="cust-1"
    )


@pytest.mark.parametrize(
    "tool_name,kwargs",
    [
        (
            "detach_security_group_rule",
            {
                "rule_id": _MASKED_RULE_KRN,
                "security_group_id": _FULL_SG_KRN,
                "vpc_id": _FULL_VPC_KRN,
            },
        ),
        (
            "attach_security_group_rule",
            {
                "rule_id": _MASKED_RULE_KRN,
                "security_group_id": _FULL_SG_KRN,
                "vpc_id": _FULL_VPC_KRN,
            },
        ),
        ("delete_security_group_rule", {"rule_id": _MASKED_RULE_KRN}),
        (
            "delete_security_group",
            {
                "security_group_id": _FULL_SG_KRN.replace(
                    "3bb55dc4-56ab-4f51-8412-d01e30ef205e", "***"
                )
            },
        ),
    ],
)
def test_security_group_rule_tools_reject_masked_krns(
    server, tool_name: str, kwargs: dict
) -> None:
    tool = server._tool_manager.get_tool(tool_name)
    with pytest.raises(ToolError, match="masked account segment"):
        tool.fn(**kwargs, region="In-Bangalore-1", confirm=True)


def test_detach_passes_through_full_krns(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.detach_rule.return_value = {"status": 200}
    srv = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    full_rule = _MASKED_RULE_KRN.replace(
        ":***:", ":3bb55dc4-56ab-4f51-8412-d01e30ef205e:"
    )
    result = srv._tool_manager.get_tool("detach_security_group_rule").fn(
        rule_id=full_rule,
        security_group_id=_FULL_SG_KRN,
        vpc_id=_FULL_VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.securityGroup.detach_rule.assert_called_once_with(
        ruleid=full_rule,
        securityid=_FULL_SG_KRN,
        vpcid=_FULL_VPC_KRN,
        x_region="In-Bangalore-1",
    )
