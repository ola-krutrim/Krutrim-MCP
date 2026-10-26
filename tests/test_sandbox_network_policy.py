"""Sandbox network policy tools and TTL=0 (krutrim-client 0.8.8)."""

import json

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from tests.test_sandbox_lifecycle import PREFIX
from tests.test_sandbox_lifecycle import harness as harness  # noqa: F401  (pytest fixture)

NETWORK = f"{PREFIX}/sandbox/sb-1/network"
TTL = f"{PREFIX}/sandbox/sb-1/ttl"
POLICY = {
    "status": 200,
    "data": {
        "id": "sb-1",
        "allowInternetAccess": True,
        "outboundDomainAllowlist": "pypi.org",
        "enforcementStatus": "applied",
    },
}


def _only(harness):
    assert len(harness.requests) == 1, [(r.method, str(r.url)) for r in harness.requests]
    return harness.requests[0]


# ------------------------------------------------------------ full replace


def test_update_network_policy_posts_full_policy(harness):
    harness.replies[("POST", NETWORK)] = (200, POLICY)
    result = harness.call(
        "update_sandbox_network_policy",
        sandbox_id="sb-1",
        allow_internet_access=True,
        outbound_cidr_allowlist=["10.0.0.0/8", "192.168.0.0/16"],
        outbound_domain_allowlist=["pypi.org", "github.com"],
        inbound_cidr_allowlist=["203.0.113.0/24"],
        confirm=True,
    )
    request = _only(harness)
    assert request.method == "POST"
    assert json.loads(request.content) == {
        "allowInternetAccess": True,
        "outboundCidrAllowlist": "10.0.0.0/8,192.168.0.0/16",
        "outboundDomainAllowlist": "pypi.org,github.com",
        "inboundCidrAllowlist": "203.0.113.0/24",
    }
    assert result.data["data"]["enforcement_status"] == "applied"


def test_update_network_policy_can_block_all_traffic(harness):
    harness.replies[("POST", NETWORK)] = (200, POLICY)
    harness.call(
        "update_sandbox_network_policy",
        sandbox_id="sb-1",
        allow_internet_access=False,
        confirm=True,
    )
    assert json.loads(_only(harness).content) == {"allowInternetAccess": False}


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"allow_internet_access": False, "outbound_domain_allowlist": ["pypi.org"]},
        {"outbound_cidr_allowlist": []},
        {"outbound_domain_allowlist": ["a.com,b.com"]},
        {"inbound_cidr_allowlist": [" "]},
    ],
)
def test_update_network_policy_rejects_bad_input_before_any_request(harness, kwargs):
    with pytest.raises(ToolError):
        harness.call("update_sandbox_network_policy", sandbox_id="sb-1", confirm=True, **kwargs)
    assert harness.requests == []


# ----------------------------------------------------------------- partial


def test_patch_network_policy_sends_only_supplied_fields(harness):
    harness.replies[("PATCH", NETWORK)] = (200, POLICY)
    harness.call(
        "patch_sandbox_network_policy",
        sandbox_id="sb-1",
        add_outbound_domains=["files.pythonhosted.org"],
        remove_outbound_domains=["github.com"],
        confirm=True,
    )
    request = _only(harness)
    assert request.method == "PATCH"
    assert json.loads(request.content) == {
        "addOutboundDomains": ["files.pythonhosted.org"],
        "removeOutboundDomains": ["github.com"],
    }


def test_patch_network_policy_replaces_a_single_allowlist(harness):
    harness.replies[("PATCH", NETWORK)] = (200, POLICY)
    harness.call(
        "patch_sandbox_network_policy",
        sandbox_id="sb-1",
        allow_internet_access=True,
        inbound_cidr_allowlist=["10.1.0.0/16", "10.2.0.0/16"],
        confirm=True,
    )
    assert json.loads(_only(harness).content) == {
        "allowInternetAccess": True,
        "inboundCidrAllowlist": "10.1.0.0/16,10.2.0.0/16",
    }


def test_patch_network_policy_empty_list_clears_an_allowlist(harness):
    harness.replies[("PATCH", NETWORK)] = (200, POLICY)
    harness.call(
        "patch_sandbox_network_policy",
        sandbox_id="sb-1",
        outbound_domain_allowlist=[],
        confirm=True,
    )
    assert json.loads(_only(harness).content) == {"outboundDomainAllowlist": ""}


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"add_outbound_domains": []},
        {"allow_internet_access": False, "inbound_cidr_allowlist": ["10.0.0.0/8"]},
        {"add_outbound_domains": ["a.com,b.com"]},
        {"remove_outbound_domains": [""]},
    ],
)
def test_patch_network_policy_rejects_bad_input_before_any_request(harness, kwargs):
    with pytest.raises(ToolError):
        harness.call("patch_sandbox_network_policy", sandbox_id="sb-1", confirm=True, **kwargs)
    assert harness.requests == []


# ------------------------------------------------------------- shared guards

MUTATIONS = [
    ("update_sandbox_network_policy", {"allow_internet_access": True}),
    ("patch_sandbox_network_policy", {"allow_internet_access": True}),
]


@pytest.mark.parametrize(("name", "kwargs"), MUTATIONS)
@pytest.mark.parametrize("confirm", [False, None, "yes", 1])
def test_network_tools_require_strict_confirmation(harness, name, kwargs, confirm):
    with pytest.raises(ToolError):
        harness.call(name, sandbox_id="sb-1", confirm=confirm, **kwargs)
    assert harness.requests == []


@pytest.mark.parametrize(("name", "kwargs"), MUTATIONS)
def test_network_tools_blocked_in_read_only_mode(harness, name, kwargs):
    harness.state.read_only = True
    with pytest.raises(ToolError, match="KRUTRIM_MCP_READ_ONLY"):
        harness.call(name, sandbox_id="sb-1", confirm=True, **kwargs)
    assert harness.requests == []


@pytest.mark.parametrize(("name", "kwargs"), MUTATIONS)
@pytest.mark.parametrize("sandbox_id", ["", "../x", "a b", "a/b"])
def test_network_tools_reject_unsafe_ids(harness, name, kwargs, sandbox_id):
    with pytest.raises(ToolError):
        harness.call(name, sandbox_id=sandbox_id, confirm=True, **kwargs)
    assert harness.requests == []


@pytest.mark.parametrize(("name", "kwargs"), MUTATIONS)
def test_network_tools_never_retry_on_server_error(harness, name, kwargs):
    harness.replies[("POST", NETWORK)] = (503, {"error": "unavailable"})
    harness.replies[("PATCH", NETWORK)] = (503, {"error": "unavailable"})
    with pytest.raises(ToolError):
        harness.call(name, sandbox_id="sb-1", confirm=True, **kwargs)
    assert len(harness.requests) == 1


def test_network_tool_reports_http_status_without_leaking_backend_body(harness):
    harness.replies[("PATCH", NETWORK)] = (409, {"error": "sandbox must be active"})
    with pytest.raises(ToolError, match="HTTP 409"):
        harness.call(
            "patch_sandbox_network_policy",
            sandbox_id="sb-1",
            allow_internet_access=True,
            confirm=True,
        )


# ---------------------------------------------------------------- TTL = 0


def test_set_ttl_zero_disables_expiry(harness):
    harness.replies[("PUT", TTL)] = (200, {"status": 200, "data": {"id": "sb-1", "ttlSeconds": 0}})
    harness.call("set_sandbox_ttl", sandbox_id="sb-1", ttl_seconds=0, confirm=True)
    assert json.loads(_only(harness).content)["ttlSeconds"] == 0


def test_set_ttl_zero_tolerates_empty_expires_at(harness):
    harness.replies[("PUT", TTL)] = httpx.Response(
        200, json={"status": 200, "data": {"id": "sb-1", "ttlSeconds": 0, "expiresAt": ""}}
    )
    result = harness.call("set_sandbox_ttl", sandbox_id="sb-1", ttl_seconds=0, confirm=True)
    assert result.ok is True


@pytest.mark.parametrize("ttl", [-1, 1, 59, 604801])
def test_set_ttl_still_rejects_values_outside_zero_or_60_to_604800(harness, ttl):
    with pytest.raises(ToolError):
        harness.call("set_sandbox_ttl", sandbox_id="sb-1", ttl_seconds=ttl, confirm=True)
    assert harness.requests == []


def test_set_ttl_description_documents_zero(harness):
    description = harness.tool("set_sandbox_ttl").description
    assert "0" in description and "never expire" in description.lower()
