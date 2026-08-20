"""DNS tool group."""

from typing import Any

from krutrim_mcp_server.tools.dns import zones


def register(mcp: Any) -> None:
    zones.register(mcp)
