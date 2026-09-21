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


def _resolve_ssh_key_uuid(ssh_key_id: str) -> str:
    """Return the key UUID the API requires, accepting a UUID or a full KRN.

    The backend returns SSH keys with a `uuid` field and a KRN in `_id`
    (there is no `id` field), and its delete endpoint accepts only the UUID.
    KRNs — including masked ones with a ':***:' account segment — carry the
    UUID as their last segment, so extract it rather than failing.
    """
    value = ssh_key_id.strip()
    if not value:
        raise ValueError("ssh_key_id must be a non-empty SSH key UUID or KRN")
    if value.startswith("krn:"):
        candidate = value.rsplit(":", 1)[-1]
        if not candidate:
            raise ValueError(f"could not extract a key UUID from KRN {value!r}")
        return candidate
    return value


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

        Each key's usable identifier is its `uuid` field (use it for
        delete_ssh_key); the API does not populate `id`, and `_id` holds the
        key's KRN.
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
        """Delete an SSH key.

        ssh_key_id is the key's `uuid` field from list_ssh_keys or the create
        response (the API does not populate `id`). A full key KRN — even one
        with a masked ':***:' account segment — is also accepted; the UUID is
        its last segment.
        """

        def _run() -> Any:
            ensure_writable(settings(), "delete_ssh_key")
            key_uuid = _resolve_ssh_key_uuid(ssh_key_id)
            ensure_confirmed(confirm, "delete_ssh_key", key_uuid)
            client = get_session().get_client()
            client.sshkey.delete_sshkey(
                key_uuid,
                x_region=resolve_region(region),
                customer_id=customer_id,
            )
            return {"deleted": True, "ssh_key_id": key_uuid}

        return run_tool(_run)
