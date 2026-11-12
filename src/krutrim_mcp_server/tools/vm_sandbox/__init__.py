"""VM Sandbox tools."""

from typing import Any

from krutrim_mcp_server.tools.vm_sandbox import (
    access,
    execution,
    lifecycle,
    network,
    operations,
    templates,
)


def register(mcp: Any) -> None:
    lifecycle.register(mcp)
    templates.register(mcp)
    operations.register(mcp)
    network.register(mcp)
    execution.register(mcp)
    access.register(mcp)
