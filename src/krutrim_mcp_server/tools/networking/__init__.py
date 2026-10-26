"""Networking tool group."""

from typing import Any

from krutrim_mcp_server.tools.networking import (
    certificates,
    load_balancers,
    ports,
    security_groups,
    vpc,
)


def register(mcp: Any) -> None:
    vpc.register(mcp)
    ports.register(mcp)
    security_groups.register(mcp)
    load_balancers.register(mcp)
    certificates.register(mcp)
