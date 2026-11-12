"""VM Sandbox template catalog and image builds."""

from typing import Annotated, Any

from pydantic import Field, StrictStr

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
    run_vm_tool,
)


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_vm_sandbox_templates(
        region: Annotated[Region, REGION_FIELD],
        limit: Annotated[Limit, Field(ge=1, le=200)] = 20,
        offset: Annotated[Offset, Field(ge=0)] = 0,
    ) -> ToolSuccess:
        """List VM Sandbox templates in the selected region.

        Platform templates include base, hermes-python, node, and python.
        Custom templates built from container images are listed too. These are
        not Sandbox templates and cannot be passed to create_sandbox.
        """

        def _run() -> Any:
            return api.list_templates(
                get_session().get_client(),
                x_region=region,
                limit=limit,
                offset=offset,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def describe_vm_sandbox_template(
        template_id: VmSandboxID,
        region: Annotated[Region, REGION_FIELD],
    ) -> ToolSuccess:
        """Read one VM Sandbox template by the id or KRN from list_vm_sandbox_templates."""

        def _run() -> Any:
            return api.retrieve_template(
                get_session().get_client(), template_id=template_id, x_region=region
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def create_vm_sandbox_template(
        name: Annotated[
            StrictStr,
            Field(min_length=2, max_length=40, pattern=r"^[a-z][a-z0-9-]{1,39}$"),
        ],
        image: Annotated[StrictStr, Field(min_length=1, max_length=255)],
        region: Annotated[Region, REGION_FIELD],
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        description: StrictStr | None = None,
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Build a custom VM Sandbox template from a public container image.

        The account can keep 10 custom templates, with 2 builds at a time.
        Platform templates are not counted. Name is 2-40 lowercase letters,
        digits, or hyphens, starts with a letter, and must not start with img-.
        Description is optional and at most 256 bytes. The image follows the
        same public amd64 registry rules as create_vm_sandbox. Building returns
        before the template is ready; poll the operation.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_vm_sandbox_template")
            ensure_confirmed(confirm, "create_vm_sandbox_template", name)
            return api.create_template(
                get_session().get_client(),
                x_region=region,
                name=name,
                image=image,
                description=description,
                idempotency_key=idempotency_key,
            )

        return run_vm_tool(_run)

    @mcp.tool()
    def delete_vm_sandbox_template(
        template_id: VmSandboxID,
        region: Annotated[Region, REGION_FIELD],
        confirm: Annotated[Confirm, CONFIRM_FIELD],
        idempotency_key: Annotated[IdempotencyKey, IDEMPOTENCY_FIELD] = None,
    ) -> ToolSuccess:
        """Delete a custom VM Sandbox template. Platform templates cannot be deleted."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_vm_sandbox_template")
            ensure_confirmed(confirm, "delete_vm_sandbox_template", template_id)
            return api.delete_template(
                get_session().get_client(),
                template_id=template_id,
                x_region=region,
                idempotency_key=idempotency_key,
            )

        return run_vm_tool(_run)
