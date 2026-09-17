"""Integration tests — skipped unless live execution and credentials are configured.

These hit a real Krutrim sandbox account. Prefer a dedicated non-prod account.
"""

from __future__ import annotations

import os

import pytest

from krutrim_mcp_server.config import resolve_api_key
from krutrim_mcp_server.server import create_server


def _credentials_configured() -> bool:
    return bool(resolve_api_key())


pytestmark = pytest.mark.skipif(
    os.environ.get("KRUTRIM_MCP_INTEGRATION") != "1" or not _credentials_configured(),
    reason="Set KRUTRIM_MCP_INTEGRATION=1 with KRUTRIM_API_KEY",
)


def test_live_list_vpcs() -> None:
    server = create_server()
    tool = server._tool_manager.get_tool("list_vpcs")
    region = os.environ.get("KRUTRIM_DEFAULT_REGION")
    if not region:
        pytest.skip("Set KRUTRIM_DEFAULT_REGION for live region-scoped tests")
    result = tool.fn(region=region)
    assert result.ok is True, result
    assert result.data is not None


def test_live_ping() -> None:
    server = create_server()
    tool = server._tool_manager.get_tool("krutrim_ping")
    result = tool.fn()
    assert result.ok is True
