"""Networking tool group."""

from typing import Any

from krutrim_mcp_server.tools.networking import ports, security_groups, vpc


def register(mcp: Any) -> None:
    vpc.register(mcp)
    ports.register(mcp)
    security_groups.register(mcp)
