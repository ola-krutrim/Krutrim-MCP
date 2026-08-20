"""Machine image MCP tools."""

from typing import Any

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.compat import sdk_raw_result
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import (
    CONFIRM_FIELD,
    REGION_FIELD,
    Region,
    resolve_region,
    run_tool,
    settings,
)


def register(mcp: Any) -> None:
    @mcp.tool()
    def create_machine_image(
        name: str,
        instance_krn: str,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a machine image from an instance."""

        def _run() -> Any:
            ensure_writable(settings(), "create_machine_image")
            ensure_confirmed(confirm, "create_machine_image", name)
            client = get_session().get_client()
            return sdk_raw_result(
                client.highlvlvpc.with_raw_response.create_image,
                name=name,
                instance_krn=instance_krn,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_image(snapshot_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete an image snapshot."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_image")
            ensure_confirmed(confirm, "delete_image", snapshot_krn)
            get_session().get_client().highlvlvpc.delete_image(snapshot_krn=snapshot_krn)
            return {"deleted": True, "snapshot_krn": snapshot_krn}

        return run_tool(_run)

    @mcp.tool()
    def delete_machine_image(image_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete a machine image."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_machine_image")
            ensure_confirmed(confirm, "delete_machine_image", image_krn)
            get_session().get_client().highlvlvpc.delete_machine_image(image_krn)
            return {"deleted": True, "image_krn": image_krn}

        return run_tool(_run)
