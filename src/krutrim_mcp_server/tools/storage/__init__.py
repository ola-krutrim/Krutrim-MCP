"""Storage tool group."""

from typing import Any

from krutrim_mcp_server.tools.storage import access_keys, storage


def register(mcp: Any) -> None:
    storage.register(mcp)
    access_keys.register(mcp)
