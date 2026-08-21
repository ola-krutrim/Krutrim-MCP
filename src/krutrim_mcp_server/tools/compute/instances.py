"""Compute (VM / image) MCP tools."""

from typing import Annotated, Any, List, Literal, Optional

from pydantic import Field

from krutrim_mcp_server.adapters.compute import (
    delete_instance_async,
    validate_compute_flavor_name,
)
from krutrim_mcp_server.adapters.compute import (
    list_compute_flavors as fetch_compute_flavors,
)
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
from krutrim_mcp_server.tools.networking.subnets import (
    SubnetId,
    validate_subnet_reference,
    verify_subnet_membership,
)

PositiveSize = Annotated[int, Field(ge=1)]
ComputeFlavorName = Annotated[
    str,
    Field(
        min_length=1,
        description=(
            "Exact selectable CPU or GPU flavor name returned by the matching "
            "regional flavor-list tool after the user chooses it."
        ),
    ),
]
InstanceFlavorType = Annotated[
    Literal["CPU", "GPU"],
    Field(
        description=(
            "Flavor catalog to validate against. Use CPU with list_compute_flavors "
            "or GPU with list_gpu_compute_flavors."
        ),
    ),
]
ExistingVolumeId = Annotated[
    str,
    Field(
        min_length=1,
        description="Full KRN of an existing Krutrim boot volume.",
    ),
]
ExistingVolumeIds = Annotated[
    List[ExistingVolumeId],
    Field(
        min_length=1,
        max_length=1,
        description=(
            "Exactly one active, unattached boot-volume KRN in the selected VPC and region. "
            "Do not use a bare UUID."
        ),
    ),
]
FAILED_INSTANCE_STATUSES = frozenset({"ERROR", "FAILED"})


def _field_value(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def _failed_instance_task_id(instance: Any) -> str | None:
    status = _field_value(instance, "status")
    task_id = _field_value(instance, "task_id")
    if not isinstance(status, str) or status.upper() not in FAILED_INSTANCE_STATUSES:
        return None
    if not isinstance(task_id, str) or not task_id.strip():
        return None
    return task_id.strip()


def _validated_existing_volume_ids(
    existing_volume_ids: List[str],
    *,
    region: str,
) -> List[str]:
    if not isinstance(existing_volume_ids, list) or len(existing_volume_ids) != 1:
        raise ValueError(
            "existing_volume_ids must contain exactly one existing boot-volume KRN"
        )

    volume_id = existing_volume_ids[0]
    if not isinstance(volume_id, str) or not volume_id.strip():
        raise ValueError("existing_volume_ids[0] must be a non-empty volume KRN")
    volume_id = volume_id.strip()
    parts = volume_id.split(":")
    if (
        len(parts) != 7
        or any(not part for part in parts)
        or parts[0] != "krn"
        or parts[1] != "kbs"
        or parts[5] != "volume"
    ):
        raise ValueError(
            "existing_volume_ids[0] must be a full Krutrim block-volume KRN, not a bare UUID"
        )
    if parts[2] != region:
        raise ValueError(
            f"existing volume region {parts[2]!r} does not match selected region {region!r}"
        )
    return [volume_id]


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_instances(
        vpc_id: str,
        region: Region = REGION_FIELD,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
    ) -> str:
        """List VM instances in a VPC
        """

        def _run() -> Any:
            client = get_session().get_client()
            kwargs: dict[str, Any] = {
                "vpc_id": vpc_id,
                "x_region": resolve_region(region),
            }
            if page is not None:
                kwargs["page"] = page
            if page_size is not None:
                kwargs["page_size"] = page_size
            return client.highlvlvpc.list_instance_info(**kwargs)

        return run_tool(_run)

    @mcp.tool()
    def describe_instance(instance_krn: str, region: Region = REGION_FIELD) -> str:
        """Describe a VM instance by KRN
        """

        def _run() -> Any:
            client = get_session().get_client()
            return client.highlvlvpc.retrieve_instance(
                krn=instance_krn, x_region=resolve_region(region)
            )

        return run_tool(_run)

    @mcp.tool()
    def search_instances(
        vpc_id: str,
        region: Region = REGION_FIELD,
        page: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> str:
        """Search VM instances in a VPC
        """

        def _run() -> Any:
            client = get_session().get_client()
            kwargs: dict[str, Any] = {
                "vpc_id": vpc_id,
                "x_region": resolve_region(region),
            }
            if page is not None:
                kwargs["page"] = page
            if limit is not None:
                kwargs["limit"] = limit
            return client.highlvlvpc.search_instances(**kwargs)

        return run_tool(_run)

    @mcp.tool()
    def list_images(
        region: Region = REGION_FIELD,
        page: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> str:
        """List machine images available in a region
        """

        def _run() -> Any:
            client = get_session().get_client()
            kwargs: dict[str, Any] = {"region_id": resolve_region(region)}
            if page is not None:
                kwargs["page"] = page
            if limit is not None:
                kwargs["limit"] = limit
            return client.highlvlvpc.list_image(**kwargs)

        return run_tool(_run)

    @mcp.tool()
    def list_compute_flavors(region: Region = REGION_FIELD) -> str:
        """List selectable CPU VM flavors for an explicit region
        """

        def _run() -> Any:
            client = get_session().get_client()
            return fetch_compute_flavors(client, x_region=resolve_region(region))

        return run_tool(_run)

    @mcp.tool()
    def list_gpu_compute_flavors(region: Region = REGION_FIELD) -> str:
        """List selectable GPU VM flavors for an explicit region
        """

        def _run() -> Any:
            client = get_session().get_client()
            return fetch_compute_flavors(
                client,
                x_region=resolve_region(region),
                flavor_type="GPU",
            )

        return run_tool(_run)

    @mcp.tool()
    def create_instance(
        instance_name: str,
        instance_type: ComputeFlavorName,
        vpc_id: str,
        subnet_id: SubnetId,
        ssh_key_name: str,
        security_group_ids: List[str],
        image_krn: Optional[str] = None,
        user_data: Optional[str] = None,
        existing_volume_ids: Optional[ExistingVolumeIds] = None,
        volume_name: Optional[str] = None,
        volume_size: Optional[PositiveSize] = None,
        volume_type: Optional[VolumeType] = None,
        floating_ip: bool = False,
        allow_public_ip: bool = False,
        delete_on_termination: bool = False,
        instance_flavor_type: InstanceFlavorType = "CPU",
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """
        Create a VM with an explicitly selected regional CPU or GPU flavor.

        Call list_compute_flavors for CPU or list_gpu_compute_flavors for GPU
        in the selected region and use the user's exact choice; no flavor default
        or fallback is used. For subnet_id, use list_subnets.subnets[].subnet_id,
        never the parent network KRN.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_instance")
            ensure_confirmed(confirm, "create_instance", instance_name)
            if floating_ip and not allow_public_ip:
                raise ValueError(
                    "floating_ip=true requires allow_public_ip=true after explicit user approval"
                )
            x_region = resolve_region(region)
            resolved_subnet_id, require_subnet_preflight = validate_subnet_reference(
                subnet_id
            )
            kwargs: dict[str, Any] = {
                "instanceName": instance_name,
                "instanceType": instance_type,
                "vpc_id": vpc_id,
                "subnet_id": resolved_subnet_id,
                "sshkey_name": ssh_key_name,
                "security_groups": security_group_ids,
                "user_data": user_data or "",
                "floating_ip": floating_ip,
                "delete_on_termination": delete_on_termination,
                "isGpu": instance_flavor_type == "GPU",
                "count": 1,
                "region": x_region,
            }

            if existing_volume_ids is not None:
                conflicting_fields = [
                    name
                    for name, value in {
                        "image_krn": image_krn,
                        "volume_name": volume_name,
                        "volume_size": volume_size,
                        "volume_type": volume_type,
                    }.items()
                    if value is not None
                ]
                if conflicting_fields:
                    raise ValueError(
                        "existing_volume_ids cannot be combined with new-volume fields: "
                        + ", ".join(conflicting_fields)
                    )
                if delete_on_termination:
                    raise ValueError(
                        "delete_on_termination must be false when reusing an existing volume"
                    )
                kwargs["volumes"] = _validated_existing_volume_ids(
                    existing_volume_ids,
                    region=x_region,
                )
            else:
                if not isinstance(image_krn, str) or not image_krn.strip():
                    raise ValueError(
                        "image_krn is required when creating a new boot volume"
                    )
                resolved_volume_size = 50 if volume_size is None else volume_size
                if type(resolved_volume_size) is not int or resolved_volume_size < 1:
                    raise ValueError("volume_size must be a positive integer")
                resolved_volume_type = volume_type or "HNSS"
                if resolved_volume_type not in ("HNSS", "HNSS_Encrypted"):
                    raise ValueError(
                        "volume_type must be either 'HNSS' or 'HNSS_Encrypted'"
                    )
                kwargs.update(
                    {
                        "image_krn": image_krn,
                        "volume_name": volume_name or f"{instance_name}-volume",
                        "volume_size": resolved_volume_size,
                        "volumetype": resolved_volume_type,
                    }
                )

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
            return client.highlvlvpc.create_instance(**kwargs)

        return run_tool(_run)

    @mcp.tool()
    def instance_action(
        instance_krn: str,
        action: Literal["start", "stop", "reboot"],
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Start, stop, or reboot a VM instance."""

        def _run() -> Any:
            ensure_writable(settings(), f"instance_action:{action}")
            ensure_confirmed(confirm, f"instance_action:{action}", instance_krn)
            client = get_session().get_client()
            return client.startStopVM.perform_action(
                instance_krn,
                action=action,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_instance(
        instance_krn: str = "",
        delete_volume: bool = False,
        failed_task_id: Optional[str] = None,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """Asynchronously delete a VM; attached-volume deletion is opt-in
        """

        def _run() -> Any:
            ensure_writable(settings(), "delete_instance")
            normalized_instance_krn = instance_krn.strip()
            normalized_failed_task_id = (
                failed_task_id.strip()
                if isinstance(failed_task_id, str) and failed_task_id.strip()
                else None
            )
            if not normalized_instance_krn and normalized_failed_task_id is None:
                raise ValueError(
                    "instance_krn is required unless failed_task_id is provided"
                )
            ensure_confirmed(
                confirm,
                "delete_instance",
                normalized_instance_krn or normalized_failed_task_id or "",
            )
            client = get_session().get_client()
            x_region = resolve_region(region)
            detail_task_id = normalized_failed_task_id
            if normalized_instance_krn:
                instance = client.highlvlvpc.retrieve_instance(
                    krn=normalized_instance_krn,
                    x_region=x_region,
                )
                detail_task_id = detail_task_id or _failed_instance_task_id(instance)
            return delete_instance_async(
                client,
                instance_krn=normalized_instance_krn,
                delete_volume=delete_volume,
                x_region=x_region,
                task_id=detail_task_id,
            )

        return run_tool(_run)
