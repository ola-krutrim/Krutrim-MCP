"""Poll VM Sandbox operations started by asynchronous mutations."""

from typing import Annotated, Any

from pydantic import Field

from krutrim_mcp_server.adapters import vm_sandbox as api
from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.tools import REGION_FIELD, Region, ToolSuccess
from krutrim_mcp_server.tools.vm_sandbox._support import VmSandboxID, run_vm_tool


def register(mcp: Any) -> None:
    @mcp.tool()
    def get_vm_sandbox_operation(
        operation_id: VmSandboxID,
        region: Annotated[Region, REGION_FIELD],
    ) -> ToolSuccess:
        """Read one VM Sandbox operation once.

        Create, delete, start, stop, resize, template build, and network update
        return an operation id before the work finishes. succeeded and failed
        are terminal. This call does not wait or cancel the operation.
        """

        def _run() -> Any:
            return api.retrieve_operation(
                get_session().get_client(),
                operation_id=operation_id,
                x_region=region,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def wait_vm_sandbox_operation(
        operation_id: VmSandboxID,
        region: Annotated[Region, REGION_FIELD],
        timeout_seconds: Annotated[float, Field(ge=1, le=600)] = 120,
        poll_interval_seconds: Annotated[float, Field(ge=0.5, le=60)] = 2,
    ) -> ToolSuccess:
        """Poll a VM Sandbox operation until it succeeds, fails, or the wait times out.

        Timing out does not cancel the server operation. Use
        get_vm_sandbox_operation to check it afterwards. A failed operation is
        returned as a tool error. The default wait is 120 seconds.
        """

        def _run() -> Any:
            return api.wait_operation(
                get_session().get_client(),
                operation_id=operation_id,
                x_region=region,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
            )

        return run_vm_tool(_run)
