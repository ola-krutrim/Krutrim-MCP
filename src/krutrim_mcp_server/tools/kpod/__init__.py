"""KPod tool group."""

from typing import Any

from krutrim_mcp_server.tools.kpod import catalog, pods


def register(mcp: Any) -> None:
    catalog.register(mcp)
    pods.register(mcp)
