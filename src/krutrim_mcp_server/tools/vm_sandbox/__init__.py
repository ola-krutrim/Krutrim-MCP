"""VM Sandbox tools for the /sandbox/v1 API.

These tools are a separate product from Sandbox (/omni/sandbox/v1).
"""

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
