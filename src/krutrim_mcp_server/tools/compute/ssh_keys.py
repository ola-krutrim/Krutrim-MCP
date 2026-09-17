"""SSH key MCP tools."""

from typing import Any

from krutrim_mcp_server.client import get_session
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
    def list_ssh_keys(
        customer_id: str,
        region: Region = REGION_FIELD,
        page: int = 1,
        limit: int = 10,
    ) -> str:
        """List SSH keys for a customer_id in a region.

        customer_id is the account UUID — the 5th segment of any full,
        unmasked KRN you own (krn:vpc:<region>:<tenant>:<customer_id>:...).
        No listing tool returns it directly; take it from a full resource KRN
        (e.g. from create_vpc / create_instance results) or from the Krutrim
        Cloud console.
        """

        def _run() -> Any:
            client = get_session().get_client()
            return client.sshkey.list_sshkeys(
                customer_id,
                x_region=resolve_region(region),
                page=page,
                limit=limit,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_ssh_key(
        key_name: str,
        public_key: str,
        customer_id: str,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create / import an SSH public key."""

        def _run() -> Any:
            ensure_writable(settings(), "create_ssh_key")
            ensure_confirmed(confirm, "create_ssh_key", key_name)
            client = get_session().get_client()
            return client.sshkey.create_sshkey(
                key_name=key_name,
                public_key=public_key,
                customer_id=customer_id,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_ssh_key(
        ssh_key_id: str,
        customer_id: str,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """Delete an SSH key."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_ssh_key")
            ensure_confirmed(confirm, "delete_ssh_key", ssh_key_id)
            client = get_session().get_client()
            client.sshkey.delete_sshkey(
                ssh_key_id,
                x_region=resolve_region(region),
                customer_id=customer_id,
            )
            return {"deleted": True, "ssh_key_id": ssh_key_id}

        return run_tool(_run)
