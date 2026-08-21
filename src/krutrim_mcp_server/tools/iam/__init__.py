"""IAM tool group."""

from typing import Any

from krutrim_mcp_server.tools.iam import iam


def register(mcp: Any) -> None:
    iam.register(mcp)
