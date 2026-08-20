"""Authenticated live KPod catalogs."""

from typing import Any

from krutrim_mcp_server.adapters.kpod import (
    list_kpod_flavors as _list_kpod_flavors,
)
from krutrim_mcp_server.adapters.kpod import (
    list_kpod_templates as _list_kpod_templates,
)
from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.tools import run_tool


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_kpod_templates() -> str:
        """List live KPod templates available to the authenticated caller.

        Use the returned pod_template_id and defaults when preparing create_kpod.
        The template catalog is global and does not accept a region or pagination.
        """

        return run_tool(lambda: _list_kpod_templates(get_session().get_client()))

    @mcp.tool()
    def list_kpod_flavors() -> str:
        """List the authenticated live KPod flavor and availability catalog.

        Use only a selectable entry's exact create_value for create_kpod. This
        authenticated catalog is live but not region-scoped, and availability is a
        point-in-time snapshot rather than a capacity reservation.
        """

        return run_tool(lambda: _list_kpod_flavors(get_session().get_client()))
