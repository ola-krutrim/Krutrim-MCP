"""Read and replace a VM Sandbox outbound egress policy."""

from typing import Annotated, Any

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import CONFIRM_FIELD, ToolSuccess, settings
from krutrim_mcp_server.tools.vm_sandbox import _service as api
from krutrim_mcp_server.tools.vm_sandbox._support import (
    IDEMPOTENCY_FIELD,
    Confirm,
    IdempotencyKey,
    VmSandboxID,
    VmSandboxNetwork,
    VmSandboxRegion,
    network_body,
    run_vm_tool,
)


def register(mcp: Any) -> None:
    @mcp.tool()
    def get_vm_sandbox_network(
        krn_id: VmSandboxID,
        region: VmSandboxRegion,
    ) -> ToolSuccess:
        """Read the VM Sandbox egress policy and whether it has been applied."""

        def _run() -> Any:
            return api.retrieve_network(
                get_session().get_client(), krn_id=krn_id, x_region=region
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def update_vm_sandbox_network(
        krn_id: VmSandboxID,
        region: VmSandboxRegion,
        network: VmSandboxNetwork,
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Replace the egress policy. Poll the returned operation.

        Use default_action deny with an allow list, or allow with a deny list.
        Each list holds at most 64 domains, *.domain names, IPv4 addresses, or CIDRs.
        """

        def _run() -> Any:
            ensure_writable(settings(), "update_vm_sandbox_network")
            ensure_confirmed(confirm, "update_vm_sandbox_network", krn_id)
            body = network_body(network)
            if body is None:
                raise ValueError("network egress policy is required")
            return api.update_network(
                get_session().get_client(),
                krn_id=krn_id,
                x_region=region,
                network=body,
                idempotency_key=idempotency_key,
            )

        return run_vm_tool(_run)
