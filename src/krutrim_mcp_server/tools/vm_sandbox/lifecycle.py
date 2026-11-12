"""VM Sandbox lifecycle tools. These call /sandbox/v1, not the Sandbox API."""

from typing import Annotated, Any, Literal

from pydantic import Field, StrictInt, StrictStr

from krutrim_mcp_server.adapters import vm_sandbox as api
from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import CONFIRM_FIELD, REGION_FIELD, Region, ToolSuccess, settings
from krutrim_mcp_server.tools.vm_sandbox._support import (
    IDEMPOTENCY_FIELD,
    Confirm,
    IdempotencyKey,
    Limit,
    Offset,
    VmSandboxID,
    VmSandboxNetwork,
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
        region: Annotated[Region, REGION_FIELD],
        status: _STATUS | None = None,
        name: StrictStr | None = None,
        limit: Annotated[Limit, Field(ge=1, le=200)] = 20,
        offset: Annotated[Offset, Field(ge=0)] = 0,
    ) -> ToolSuccess:
        """List VM Sandboxes in the selected region.

        This is the VM Sandbox product (/sandbox/v1), not Sandbox
        (/omni/sandbox/v1). Filter by exact lifecycle status or name. Results
        use limit/offset pagination.
        """

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
        region: Annotated[Region, REGION_FIELD],
    ) -> ToolSuccess:
        """Read one VM Sandbox by its exact KRN. Does not start it or change its expiry."""

        def _run() -> Any:
            return api.retrieve_sandbox(
                get_session().get_client(), krn_id=krn_id, x_region=region
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def list_vm_sandbox_flavors(
        region: Annotated[Region, REGION_FIELD],
        limit: Annotated[Limit, Field(ge=1, le=200)] = 20,
        offset: Annotated[Offset, Field(ge=0)] = 0,
    ) -> ToolSuccess:
        """List VM Sandbox flavors in the selected region.

        Use the exact flavor name with create_vm_sandbox or resize_vm_sandbox.
        The platform limit is 4 vCPU and 8 GiB. Reported size and cost are a
        live snapshot, not a capacity guarantee. These flavors are not Sandbox
        flavors and are not interchangeable with list_sandbox_flavors.
        """

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
        region: Annotated[Region, REGION_FIELD],
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

        This is not create_sandbox. Call list_vm_sandbox_flavors and
        list_vm_sandbox_templates first and pass an exact flavor name at or
        below 4 vCPU and 8 GiB. Pass template or image, not both. Omit both to
        use the service default template (base in the console). Other platform
        templates include hermes-python, node, and python. A container image
        must be a public linux/amd64 reference of at most 255 characters from
        Docker Hub, GHCR, Quay, ECR Public, GCR, registry.k8s.io, MCR, or
        GitLab, and it should be Debian or Ubuntu based. The first use of an
        image builds a template.
        Environment names cannot start with KRUTRIM_ or SPACE_, and at most 64
        variables / 32 KiB are accepted. Values are not returned later.
        Outbound policy, when set, is an egress object: default_action deny
        with allow lists only those destinations; default_action allow with
        deny blocks those destinations. Omit network for the platform default.
        Each list holds at most 64 domains, *.domain names, IPv4 addresses, or
        IPv4 CIDRs. URLs, ports, and IPv6 are rejected.
        Expiry defaults to one hour when ttl_seconds is omitted. Supported
        duration is 1 minute to 7 days (60–604800 seconds). Explain that expiry
        before confirmation. Creation returns before the sandbox is ready;
        poll get_vm_sandbox_operation or wait_vm_sandbox_operation. A wait
        timeout does not cancel the operation.
        The console form also has a boot command. This API has no
        startup-script field, so none is sent.
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
        region: Annotated[Region, REGION_FIELD],
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Delete one VM Sandbox. The request returns before deletion finishes.

        Poll the returned operation. A deleted sandbox can remain visible in
        list_vm_sandboxes until that operation succeeds. Do not retry blindly.
        """

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
        region: Annotated[Region, REGION_FIELD],
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
        region: Annotated[Region, REGION_FIELD],
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Stop a VM Sandbox. Files are kept and running processes end.

        The call returns immediately; poll the operation. A stopped sandbox
        keeps billing until it is deleted or its expiry is reached.
        """

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
        region: Annotated[Region, REGION_FIELD],
        ttl_seconds: Annotated[StrictInt, Field(ge=60, le=604800)],
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Add ttl_seconds to the current VM Sandbox expiry.

        This does not set an absolute lifetime and cannot turn expiry off.
        Pass 60–604800 seconds (1 minute to 7 days). It is not set_sandbox_ttl.
        """

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
        region: Annotated[Region, REGION_FIELD],
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
        region: Annotated[Region, REGION_FIELD],
    ) -> ToolSuccess:
        """Read metered usage for one VM Sandbox. Does not change the sandbox."""

        def _run() -> Any:
            return api.sandbox_usage(
                get_session().get_client(), krn_id=krn_id, x_region=region
            )

        return run_vm_tool(_run)
