"""VM Sandbox lifecycle tools."""

from typing import Annotated, Any, Literal

from pydantic import Field, StrictInt, StrictStr

from krutrim_mcp_server.adapters import vm_sandbox as api
from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import CONFIRM_FIELD, ToolSuccess, settings
from krutrim_mcp_server.tools.vm_sandbox._support import (
    IDEMPOTENCY_FIELD,
    Confirm,
    IdempotencyKey,
    Limit,
    Offset,
    VmSandboxID,
    VmSandboxNetwork,
    VmSandboxRegion,
    network_body,
    run_vm_tool,
)

_TTL = Annotated[
    StrictInt | None,
    Field(
        description=(
            "Optional expiry added from creation. Supported duration is 1 minute to "
            "7 days (60–604800 seconds). Omit it to use the service default of one "
            "hour (3600 seconds). This cannot disable expiry."
        )
    ),
]
_STATUS = Literal[
    "PROVISIONING",
    "ACTIVE",
    "STOPPING",
    "DOWN",
    "STARTING",
    "RESIZING",
    "DELETING",
    "FAILED",
    "LOST",
]
_ENV = dict[StrictStr, StrictStr] | None


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_vm_sandboxes(
        region: VmSandboxRegion,
        status: _STATUS | None = None,
        name: StrictStr | None = None,
        limit: Annotated[Limit, Field(ge=1, le=200)] = 20,
        offset: Annotated[Offset, Field(ge=0)] = 0,
    ) -> ToolSuccess:
        """List VM Sandboxes. Optionally filter by status or name."""

        def _run() -> Any:
            return api.list_sandboxes(
                get_session().get_client(),
                x_region=region,
                status=status,
                name=name,
                limit=limit,
                offset=offset,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def describe_vm_sandbox(
        krn_id: VmSandboxID,
        region: VmSandboxRegion,
    ) -> ToolSuccess:
        """Read one VM Sandbox by its exact KRN. Does not start it or change its expiry."""

        def _run() -> Any:
            return api.retrieve_sandbox(
                get_session().get_client(), krn_id=krn_id, x_region=region
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def list_vm_sandbox_flavors(
        region: VmSandboxRegion,
        limit: Annotated[Limit, Field(ge=1, le=200)] = 20,
        offset: Annotated[Offset, Field(ge=0)] = 0,
    ) -> ToolSuccess:
        """List VM Sandbox flavors. Use an exact name at or below 4 vCPU and 8 GiB."""

        def _run() -> Any:
            return api.list_flavors(
                get_session().get_client(),
                x_region=region,
                limit=limit,
                offset=offset,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def create_vm_sandbox(
        name: Annotated[
            StrictStr,
            Field(
                min_length=1,
                max_length=64,
                pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$",
            ),
        ],
        region: VmSandboxRegion,
        flavor: StrictStr,
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        template: StrictStr | None = None,
        image: Annotated[StrictStr | None, Field(max_length=255)] = None,
        ttl_seconds: _TTL = None,
        env: _ENV = None,
        network: VmSandboxNetwork | None = None,
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Create a VM Sandbox from a template or a public container image.

        Call list_vm_sandbox_flavors and list_vm_sandbox_templates first. Pass
        an exact flavor at or below 4 vCPU and 8 GiB, and a template or an image,
        not both. Omit both to use the default template. Images must be public
        linux/amd64 references of at most 255 characters. Environment names cannot
        start with KRUTRIM_ or SPACE_ (at most 64 variables, 32 KiB). Expiry
        defaults to one hour (60–604800 seconds). The call returns an operation;
        poll it with wait_vm_sandbox_operation. A timeout does not cancel it.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_vm_sandbox")
            ensure_confirmed(confirm, "create_vm_sandbox", name)
            return api.create_sandbox(
                get_session().get_client(),
                x_region=region,
                name=name,
                flavor=flavor,
                template=template,
                image=image,
                ttl_seconds=ttl_seconds,
                env=env,
                network=network_body(network),
                idempotency_key=idempotency_key,
            )

        secret_values = (
            tuple(value for value in env.values() if isinstance(value, str) and value)
            if isinstance(env, dict)
            else ()
        )
        return run_vm_tool(_run, secret_values)

    @mcp.tool()
    def delete_vm_sandbox(
        krn_id: VmSandboxID,
        region: VmSandboxRegion,
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Delete one VM Sandbox. Poll the returned operation; do not retry blindly."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_vm_sandbox")
            ensure_confirmed(confirm, "delete_vm_sandbox", krn_id)
            return api.delete_sandbox(
                get_session().get_client(),
                krn_id=krn_id,
                x_region=region,
                idempotency_key=idempotency_key,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def start_vm_sandbox(
        krn_id: VmSandboxID,
        region: VmSandboxRegion,
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Start a stopped VM Sandbox. The call returns immediately; poll the operation."""

        def _run() -> Any:
            ensure_writable(settings(), "start_vm_sandbox")
            ensure_confirmed(confirm, "start_vm_sandbox", krn_id)
            return api.start_sandbox(
                get_session().get_client(),
                krn_id=krn_id,
                x_region=region,
                idempotency_key=idempotency_key,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def stop_vm_sandbox(
        krn_id: VmSandboxID,
        region: VmSandboxRegion,
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Stop a VM Sandbox. Files are kept and running processes end. Poll the operation."""

        def _run() -> Any:
            ensure_writable(settings(), "stop_vm_sandbox")
            ensure_confirmed(confirm, "stop_vm_sandbox", krn_id)
            return api.stop_sandbox(
                get_session().get_client(),
                krn_id=krn_id,
                x_region=region,
                idempotency_key=idempotency_key,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def extend_vm_sandbox_ttl(
        krn_id: VmSandboxID,
        region: VmSandboxRegion,
        ttl_seconds: Annotated[StrictInt, Field(ge=60, le=604800)],
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Add ttl_seconds (60–604800) to the current expiry. Cannot turn expiry off."""

        def _run() -> Any:
            ensure_writable(settings(), "extend_vm_sandbox_ttl")
            ensure_confirmed(confirm, "extend_vm_sandbox_ttl", krn_id)
            return api.extend_sandbox(
                get_session().get_client(),
                krn_id=krn_id,
                x_region=region,
                ttl_seconds=ttl_seconds,
                idempotency_key=idempotency_key,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def resize_vm_sandbox(
        krn_id: VmSandboxID,
        region: VmSandboxRegion,
        flavor: StrictStr,
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Resize a VM Sandbox to another flavor at or below 4 vCPU and 8 GiB.

        Disk files are kept. Running processes and memory are discarded. The
        call returns immediately; poll the operation before depending on the
        new size. Choose the exact name from list_vm_sandbox_flavors.
        """

        def _run() -> Any:
            ensure_writable(settings(), "resize_vm_sandbox")
            ensure_confirmed(confirm, "resize_vm_sandbox", krn_id)
            return api.resize_sandbox(
                get_session().get_client(),
                krn_id=krn_id,
                x_region=region,
                flavor=flavor,
                idempotency_key=idempotency_key,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def get_vm_sandbox_usage(
        krn_id: VmSandboxID,
        region: VmSandboxRegion,
    ) -> ToolSuccess:
        """Read metered usage for one VM Sandbox. Does not change the sandbox."""

        def _run() -> Any:
            return api.sandbox_usage(
                get_session().get_client(), krn_id=krn_id, x_region=region
            )

        return run_vm_tool(_run)
