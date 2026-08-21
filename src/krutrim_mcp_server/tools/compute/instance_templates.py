"""VM instance-template and batch-create MCP tools."""

from typing import Annotated, Any, List, Optional

from pydantic import Field

from krutrim_mcp_server.adapters.compute import validate_compute_flavor_name
from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import (
    CONFIRM_FIELD,
    REGION_FIELD,
    Region,
    VolumeType,
    resolve_region,
    run_tool,
    settings,
)
from krutrim_mcp_server.tools.compute.instances import (
    ComputeFlavorName,
    InstanceFlavorType,
)
from krutrim_mcp_server.tools.networking.subnets import (
    SubnetId,
    validate_subnet_reference,
    verify_subnet_membership,
)

Page = Annotated[int, Field(ge=1)]
PageSize = Annotated[int, Field(ge=1, le=100)]
PositiveCount = Annotated[int, Field(ge=1)]
TemplateKrn = Annotated[
    str,
    Field(
        min_length=1,
        description=(
            "Full Krutrim VM instance-template KRN from list_instance_templates. "
            "Do not use a display name or bare UUID."
        ),
    ),
]
SecurityGroupIds = Annotated[
    List[str],
    Field(
        min_length=1,
        description="One or more security-group IDs for instances created from the template.",
    ),
]


def _validated_template_krn(template_krn: str, *, region: str) -> str:
    if not isinstance(template_krn, str) or not template_krn.strip():
        raise ValueError("template_krn must be a non-empty full instance-template KRN")
    value = template_krn.strip()
    parts = value.split(":")
    resource_markers = {"template", "instance-template", "instance_template"}
    if (
        len(parts) < 5
        or any(not part for part in parts)
        or parts[0] != "krn"
        or parts[1] != "vm"
        or not resource_markers.intersection(parts[3:-1])
    ):
        raise ValueError(
            "template_krn must be a full Krutrim VM instance-template KRN, "
            "not a display name or bare UUID"
        )
    if parts[2] != region:
        raise ValueError(
            f"instance-template region {parts[2]!r} does not match selected region {region!r}"
        )
    return value


def _validated_security_group_ids(security_group_ids: List[str]) -> List[str]:
    if not isinstance(security_group_ids, list) or not security_group_ids:
        raise ValueError("security_group_ids must contain at least one security-group ID")
    if any(not isinstance(value, str) or not value.strip() for value in security_group_ids):
        raise ValueError("security_group_ids must contain only non-empty strings")
    return [value.strip() for value in security_group_ids]


def _template_krn_from_response(template: Any) -> str | None:
    if isinstance(template, dict):
        value = template.get("template_krn")
    else:
        value = getattr(template, "template_krn", None)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _retrieve_exact_template(client: Any, *, template_krn: str, region: str) -> Any:
    template = client.highlvlvpc.retrieve_instance_template(
        template_krn=template_krn,
        x_region=region,
    )
    resolved_krn = _template_krn_from_response(template)
    if resolved_krn != template_krn:
        raise ValueError(
            "instance-template identity preflight did not return the exact requested KRN; "
            "the mutation was not sent"
        )
    return template


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_instance_templates(
        region: Region = REGION_FIELD,
        page: Optional[Page] = None,
        limit: Optional[PageSize] = None,
    ) -> str:
        """List VM instance templates in an explicitly selected region."""

        def _run() -> Any:
            kwargs: dict[str, Any] = {"x_region": resolve_region(region)}
            if page is not None:
                kwargs["page"] = page
            if limit is not None:
                kwargs["limit"] = limit
            return get_session().get_client().highlvlvpc.list_instance_templates(**kwargs)

        return run_tool(_run)

    @mcp.tool()
    def describe_instance_template(
        template_krn: TemplateKrn,
        region: Region = REGION_FIELD,
    ) -> str:
        """Describe one VM instance template by its full KRN."""

        def _run() -> Any:
            x_region = resolve_region(region)
            resolved_krn = _validated_template_krn(template_krn, region=x_region)
            return _retrieve_exact_template(
                get_session().get_client(),
                template_krn=resolved_krn,
                region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_instance_template(
        template_name: str,
        instance_type: ComputeFlavorName,
        vpc_id: str,
        subnet_id: SubnetId,
        ssh_key_name: str,
        security_group_ids: SecurityGroupIds,
        image_krn: str,
        volume_name: str,
        volume_size: PositiveCount,
        volume_type: VolumeType,
        user_data: Optional[str] = None,
        instance_flavor_type: InstanceFlavorType = "CPU",
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a reusable VM template from an explicitly selected regional flavor.

        This creates only the template. It does not launch instances. Call the matching
        CPU or GPU flavor-list tool first and use the user's exact selected flavor.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_instance_template")
            ensure_confirmed(confirm, "create_instance_template", template_name)
            x_region = resolve_region(region)
            resolved_subnet_id, require_subnet_preflight = validate_subnet_reference(
                subnet_id
            )
            if type(volume_size) is not int or volume_size < 1:
                raise ValueError("volume_size must be a positive integer")
            resolved_security_groups = _validated_security_group_ids(security_group_ids)
            client = get_session().get_client()
            if require_subnet_preflight:
                verify_subnet_membership(
                    client,
                    vpc_id=vpc_id,
                    subnet_id=resolved_subnet_id,
                    region=x_region,
                )
            validate_compute_flavor_name(
                client,
                flavor_name=instance_type,
                x_region=x_region,
                flavor_type=instance_flavor_type,
            )
            return client.highlvlvpc.create_instance_template(
                name=template_name,
                vpc_id=vpc_id,
                subnet_id=resolved_subnet_id,
                instanceType=instance_type,
                sshkey_name=ssh_key_name,
                region=x_region,
                image_krn=image_krn,
                volumetype=volume_type,
                volume_size=volume_size,
                volume_name=volume_name,
                security_groups=resolved_security_groups,
                isGpu=instance_flavor_type == "GPU",
                user_data=user_data or "",
            )

        return run_tool(_run)

    @mcp.tool()
    def batch_create_vms(
        template_krn: TemplateKrn,
        count: PositiveCount,
        instance_name: str,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a confirmed billable batch of VMs from one exact template.

        The response is an asynchronous batch job. Reconcile the requested names with
        search_instances before retrying a timeout; a retry can create another batch.
        """

        def _run() -> Any:
            ensure_writable(settings(), "batch_create_vms")
            ensure_confirmed(
                confirm,
                "batch_create_vms",
                f"{count} VMs from {template_krn} with base name {instance_name}",
            )
            if type(count) is not int or count < 1:
                raise ValueError("count must be a positive integer")
            if not isinstance(instance_name, str) or not instance_name.strip():
                raise ValueError("instance_name must be a non-empty string")
            x_region = resolve_region(region)
            resolved_krn = _validated_template_krn(template_krn, region=x_region)
            client = get_session().get_client()
            _retrieve_exact_template(
                client,
                template_krn=resolved_krn,
                region=x_region,
            )
            return client.highlvlvpc.batch_create_vms(
                template_krn=resolved_krn,
                count=count,
                instanceName=instance_name.strip(),
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_instance_template(
        template_krn: TemplateKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Delete one exact VM instance template after an identity preflight."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_instance_template")
            ensure_confirmed(confirm, "delete_instance_template", template_krn)
            x_region = resolve_region(region)
            resolved_krn = _validated_template_krn(template_krn, region=x_region)
            client = get_session().get_client()
            _retrieve_exact_template(
                client,
                template_krn=resolved_krn,
                region=x_region,
            )
            return client.highlvlvpc.delete_instance_template(
                template_krn=resolved_krn,
                x_region=x_region,
            )

        return run_tool(_run)
