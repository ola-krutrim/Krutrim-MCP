"""Kubernetes tool group."""

from typing import Any

from krutrim_mcp_server.tools.kubernetes import kks


def register(mcp: Any) -> None:
    kks.register(mcp)
