"""Meta / health MCP tools."""

from __future__ import annotations

from typing import Any

from krutrim_mcp_server._version import __version__
from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.config import KNOWN_REGIONS
from krutrim_mcp_server.tools import run_tool


def register(mcp: Any) -> None:
    @mcp.tool()
    def krutrim_ping() -> str:
        """Health check for the Krutrim Cloud MCP server (no cloud API call)."""

        def _run() -> dict[str, Any]:
            session = get_session()
            health = session.health()
            return {
                "ok": True,
                "server": "krutrim-mcp-server",
                "version": __version__,
                "session": health,
            }

        return run_tool(_run)

    @mcp.tool()
    def list_regions() -> str:
        """List known Krutrim Cloud regions used with the x-region header."""

        def _run() -> dict[str, Any]:
            session = get_session()
            return {
                "regions": list(KNOWN_REGIONS),
                "default_region": session.settings.default_region,
                "note": (
                    "Region-scoped tools require an explicit region selection. "
                    "KRUTRIM_DEFAULT_REGION is reported for context, not used to "
                    "silently choose a region for tool calls."
                ),
            }

        return run_tool(_run)
