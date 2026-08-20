"""Compute tool group."""

from typing import Any

from krutrim_mcp_server.tools.compute import (
    auto_scaling,
    images,
    instance_templates,
    instances,
    ssh_keys,
)


def register(mcp: Any) -> None:
    instances.register(mcp)
    instance_templates.register(mcp)
    images.register(mcp)
    ssh_keys.register(mcp)
    auto_scaling.register(mcp)
