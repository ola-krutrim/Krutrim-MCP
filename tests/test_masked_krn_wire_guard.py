"""Wire-level masked-KRN guard: every tool is protected, not just SG rules.

The guard is an httpx request event hook installed by
patch_client_compatibility, so any request whose URL (percent-encoded or
not) or body carries a ':***:' masked KRN fails locally with an actionable
message instead of an opaque backend 400/404 — across all current and
future tools.
"""

from __future__ import annotations

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.compat import _reject_masked_krns_in_request
from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.errors import format_error
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


_MASKED_VPC = "krn:vpc:In-Bangalore-1:9167252691:***:vpc:5d146d79-a800-462d-8f1e-f02859242ffa"


def test_hook_rejects_masked_krn_in_percent_encoded_url() -> None:
    request = httpx.Request(
        "GET",
        "https://cloud.olakrutrim.com/v1/x",
        params={"vpc_id": _MASKED_VPC},
    )
    assert "%2A%2A%2A" in str(request.url)
    with pytest.raises(ValueError, match="masked Krutrim KRN"):
        _reject_masked_krns_in_request(request)


def test_hook_rejects_masked_krn_in_path_and_body() -> None:
    with pytest.raises(ValueError, match="masked Krutrim KRN"):
        _reject_masked_krns_in_request(
            httpx.Request("DELETE", f"https://cloud.olakrutrim.com/v1/x/{_MASKED_VPC}")
        )
    with pytest.raises(ValueError, match="masked Krutrim KRN"):
        _reject_masked_krns_in_request(
            httpx.Request(
                "POST",
                "https://cloud.olakrutrim.com/v1/x",
                json={"vpc_id": _MASKED_VPC},
            )
        )


def test_hook_allows_full_krns_and_plain_requests() -> None:
    full = _MASKED_VPC.replace(":***:", ":3bb55dc4-56ab-4f51-8412-d01e30ef205e:")
    _reject_masked_krns_in_request(
        httpx.Request(
            "POST",
            f"https://cloud.olakrutrim.com/v1/x/{full}",
            json={"vpc_id": full, "note": "a ** b *** c"},
        )
    )
    _reject_masked_krns_in_request(
        httpx.Request("GET", "https://cloud.olakrutrim.com/v1/x")
    )


def test_format_error_unwraps_guard_from_transport_wrapper() -> None:
    guard_error = ValueError(
        "Request URL '...' contains a masked Krutrim KRN (':***:')."
    )
    try:
        try:
            raise guard_error
        except ValueError as inner:
            raise ConnectionError("Connection error.") from inner
    except ConnectionError as wrapped:
        message = format_error(wrapped)
    assert "masked Krutrim KRN" in message
    assert "Connection error" not in message


@pytest.mark.parametrize(
    "tool_name,kwargs",
    [
        ("delete_vpc", {"vpc_id": _MASKED_VPC, "region": "In-Bangalore-1", "confirm": True}),
        ("list_instances", {"vpc_id": _MASKED_VPC, "region": "In-Bangalore-1"}),
        (
            "describe_instance",
            {
                "instance_krn": "krn:vm:In-Bangalore-1:9167252691:***:instance:abc",
                "region": "In-Bangalore-1",
            },
        ),
        (
            "delete_kks_cluster",
            {
                "cluster_krn": "krn:kks:In-Bangalore-1:9167252691:***:cluster:x",
                "confirm": True,
            },
        ),
        (
            "delete_kpod",
            {"kpod_krn": "krn:kpod:In-Bangalore-1:9167252691:***:kpod:y", "confirm": True},
        ),
    ],
)
def test_tools_fail_fast_on_masked_krns_without_network(
    tool_name: str, kwargs: dict
) -> None:
    # base_url is real, but the guard must trip before any socket is opened;
    # an auth/connection error here would mean the request reached the wire.
    srv = create_server(_settings())
    tool = srv._tool_manager.get_tool(tool_name)
    with pytest.raises(ToolError, match="masked Krutrim KRN"):
        tool.fn(**kwargs)
