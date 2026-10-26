"""Machine image MCP tools."""

from typing import Any, Literal

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

DiskFormat = Literal["qcow2", "vhd", "vhdx", "vmdk", "raw", "iso"]


def _validate_image_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("image_url must be a non-empty URL")
    url = value.strip()
    if any(char.isspace() for char in url):
        raise ValueError("image_url must not contain whitespace")
    if not url.startswith(("http://", "https://")):
        raise ValueError("image_url must start with http:// or https://")
    return url


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
    def upload_image_s3(
        image_url: str,
        disk_format: DiskFormat,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Import a VM image into Krutrim Cloud from an HTTP(S) URL (for example S3).

        Krutrim Cloud downloads the image from image_url, so it must be reachable
        from the internet - use a pre-signed URL for private buckets. disk_format is
        one of qcow2, vhd, vhdx, vmdk, raw or iso. The import is asynchronous; check
        list_images afterwards.
        """

        def _run() -> Any:
            ensure_writable(settings(), "upload_image_s3")
            ensure_confirmed(confirm, "upload_image_s3", image_url)
            url = _validate_image_url(image_url)
            x_region = resolve_region(region)
            client = get_session().get_client()
            return sdk_raw_result(
                client.highlvlvpc.with_raw_response.upload_image_s3,
                x_region,
                disk_format=str(disk_format).lower(),
                image=url,
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
