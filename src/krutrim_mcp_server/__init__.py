"""Krutrim Cloud MCP server — core infrastructure tools for AI clients."""

from __future__ import annotations

from krutrim_mcp_server._version import __version__

__all__ = ["create_server", "main", "__version__"]


def __getattr__(name: str):
    if name in {"create_server", "main"}:
        from krutrim_mcp_server.server import create_server, main

        return {"create_server": create_server, "main": main}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
