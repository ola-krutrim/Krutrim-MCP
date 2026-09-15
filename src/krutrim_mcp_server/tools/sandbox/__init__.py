"""Sandbox catalogs, lifecycle, files, commands, ports, and proxy tools."""

from typing import Any

from krutrim_mcp_server.tools.sandbox import execution, files, lifecycle


def register(mcp: Any) -> None:
    lifecycle.register(mcp)
    files.register(mcp)
    execution.register(mcp)
