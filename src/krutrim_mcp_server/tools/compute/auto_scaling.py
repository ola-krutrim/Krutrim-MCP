"""Auto-scaling group MCP tools."""

from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.compat import sdk_raw_result, sdk_response_json
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import (
    CONFIRM_FIELD,
    REGION_FIELD,
    Region,
    resolve_region,
    run_tool,
    settings,
)
from krutrim_mcp_server.tools.networking.subnets import (
    SubnetId,
    validate_subnet_reference,
    verify_subnet_membership,
)
from krutrim_mcp_server.tools.shared.common import drop_none

Page = Annotated[int, Field(ge=1)]
PageSize = Annotated[int, Field(ge=1, le=100)]
PositiveCount = Annotated[int, Field(ge=1)]
NonNegativeCount = Annotated[int, Field(ge=0)]
ASGMutationRegion = Annotated[
    Literal["In-Bangalore-1"],
    Field(
        description=(
            "ASG mutations are limited to In-Bangalore-1 by krutrim-client 0.5.9; "
            "Hyderabad must not be inferred or forced."
        )
    ),
]
ASG_REGION_FIELD = Field(
    ...,
    description=(
        "Select In-Bangalore-1 for this ASG mutation. krutrim-client 0.5.9 rejects "
        "Hyderabad for this operation."
    ),
)


class ASGVolume(BaseModel):
    """Validated ASG volume entry matching krutrim-client's VolumeParam."""

    model_config = ConfigDict(extra="forbid")

    count: int = Field(ge=1)
    volume_size: int = Field(ge=1)
    volume_name: str | None = None
    volume_type: str | None = None


def _volume_payload(volumes: list[ASGVolume | dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        ASGVolume.model_validate(volume).model_dump(exclude_none=True)
        for volume in volumes
    ]


def _validate_scaling_bounds(min_count: int | None, max_count: int | None) -> None:
    if min_count is not None and min_count < 0:
        raise ValueError("min_count must be greater than or equal to 0")
    if max_count is not None and max_count < 1:
        raise ValueError("max_count must be greater than 0")
    if min_count is not None and max_count is not None and min_count > max_count:
        raise ValueError("min_count must be less than or equal to max_count")


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_asgs_by_vpc(
        vpc_krn: str,
        page: Page = 1,
        size: PageSize = 50,
    ) -> str:
        """List auto-scaling groups by VPC."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.asg.with_raw_response.get_asg_krn_by_vpc,
                vpc_krn=vpc_krn,
                page=page,
                size=size,
            )

        return run_tool(_run)

    @mcp.tool()
    def list_asgs(
        asg_krn: Optional[str] = None,
        asg_name: Optional[str] = None,
        page: Page = 1,
        size: PageSize = 50,
        region: Region = REGION_FIELD,
    ) -> str:
        """Retrieve/list auto-scaling groups."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.asgV1.with_raw_response.retrieve_asg,
                **drop_none(
                    {
                        "asg_krn": asg_krn,
                        "asg_name": asg_name,
                        "page": page,
                        "size": size,
                        "x_region": resolve_region(region),
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def create_asg(
        asg_name: str,
        vpc_name: str,
        vpc_krn: str,
        subnet_id: SubnetId,
        image_krn: str,
        instance_name: str,
        instance_type: str,
        min_count: NonNegativeCount,
        max_count: PositiveCount,
        policy: list[dict[str, Any]],
        security_groups: list[str],
        sshkey_name: str,
        volume_name: str,
        volume_size: list[ASGVolume],
        volume_type: str,
        save_as_template: bool = False,
        launch_from_template: bool = False,
        launch_template_id: Optional[str] = None,
        launch_template_version: Optional[int] = None,
        user_data: Optional[str] = None,
        region: ASGMutationRegion = ASG_REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create an auto-scaling group."""

        def _run() -> Any:
            ensure_writable(settings(), "create_asg")
            ensure_confirmed(confirm, "create_asg", asg_name)
            _validate_scaling_bounds(min_count, max_count)
            x_region = resolve_region(region)
            resolved_subnet_id, require_subnet_preflight = validate_subnet_reference(
                subnet_id
            )
            client = get_session().get_client()
            if require_subnet_preflight:
                verify_subnet_membership(
                    client,
                    vpc_id=vpc_krn,
                    subnet_id=resolved_subnet_id,
                    region=x_region,
                )
            return client.asgV1.create_asg(
                asg_name=asg_name,
                vpc_name=vpc_name,
                vpc_krn=vpc_krn,
                subnet_id=resolved_subnet_id,
                image_krn=image_krn,
                instance_name=instance_name,
                instance_type=instance_type,
                min=min_count,
                max=max_count,
                policy=policy,
                region=x_region,
                security_groups=security_groups,
                sshkey_name=sshkey_name,
                volume_name=volume_name,
                volume_size=_volume_payload(volume_size),
                volume_type=volume_type,
                save_as_template=save_as_template,
                launch_from_template=launch_from_template,
                x_region=x_region,
                **drop_none(
                    {
                        "launch_template_id": launch_template_id,
                        "launch_template_version": launch_template_version,
                        "user_data": user_data,
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def update_asg(
        asg_krn: str,
        instance_type: Optional[str] = None,
        min_count: Optional[NonNegativeCount] = None,
        max_count: Optional[PositiveCount] = None,
        policy: Optional[list[dict[str, Any]]] = None,
        security_groups: Optional[list[str]] = None,
        sshkey_name: Optional[str] = None,
        volume_size: Optional[list[ASGVolume]] = None,
        volume_name: Optional[str] = None,
        user_data: Optional[str] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Update an auto-scaling group."""

        def _run() -> Any:
            ensure_writable(settings(), "update_asg")
            ensure_confirmed(confirm, "update_asg", asg_krn)
            _validate_scaling_bounds(min_count, max_count)
            client = get_session().get_client()
            return sdk_raw_result(
                client.asgV1.with_raw_response.update_asg,
                asg_krn=asg_krn,
                **drop_none(
                    {
                        "instance_type": instance_type,
                        "min": min_count,
                        "max": max_count,
                        "policy": policy,
                        "security_groups": security_groups,
                        "sshkey_name": sshkey_name,
                        "volume_size": (
                            None if volume_size is None else _volume_payload(volume_size)
                        ),
                        "volume_name": volume_name,
                        "user_data": user_data,
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_asg(asg_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete an auto-scaling group."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_asg")
            ensure_confirmed(confirm, "delete_asg", asg_krn)
            client = get_session().get_client()
            return sdk_raw_result(client.asgV1.with_raw_response.delete_asg, asg_krn)

        return run_tool(_run)

    @mcp.tool()
    def upscale_asg(
        asg_krn: str,
        desired_vm_count: PositiveCount,
        vpc_krn: str,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Upscale an auto-scaling group."""

        def _run() -> Any:
            ensure_writable(settings(), "upscale_asg")
            ensure_confirmed(confirm, "upscale_asg", asg_krn)
            client = get_session().get_client()
            return sdk_raw_result(
                client.asgV1.with_raw_response.upscale_asg,
                asg_krn=asg_krn,
                desired_vm_count=desired_vm_count,
                vpc_krn=vpc_krn,
            )

        return run_tool(_run)

    @mcp.tool()
    def downscale_asg(
        asg_krn: str,
        count: PositiveCount,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Downscale an auto-scaling group."""

        def _run() -> Any:
            ensure_writable(settings(), "downscale_asg")
            ensure_confirmed(confirm, "downscale_asg", asg_krn)
            client = get_session().get_client()
            return sdk_raw_result(
                client.asgV1.with_raw_response.downscale_asg,
                asg_krn=asg_krn,
                count=count,
            )

        return run_tool(_run)

    @mcp.tool()
    def list_launch_templates(
        vpc_id: str,
        page: Page = 1,
        size: PageSize = 50,
        region: Region = REGION_FIELD,
    ) -> str:
        """List ASG launch templates."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.asgV1.with_raw_response.get_launch_templates,
                vpc_id=vpc_id,
                page=page,
                size=size,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def create_launch_template(
        template_name: str,
        vpc_name: str,
        vpc_krn: str,
        subnet_id: SubnetId,
        image_krn: str,
        instance_name: str,
        instance_type: str,
        min_count: NonNegativeCount,
        max_count: PositiveCount,
        policy: list[dict[str, Any]],
        security_groups: list[str],
        sshkey_name: str,
        volume_name: str,
        volume_size: list[ASGVolume],
        volume_type: str,
        user_data: Optional[str] = None,
        region: ASGMutationRegion = ASG_REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create an ASG launch template."""

        def _run() -> Any:
            ensure_writable(settings(), "create_launch_template")
            ensure_confirmed(confirm, "create_launch_template", template_name)
            _validate_scaling_bounds(min_count, max_count)
            x_region = resolve_region(region)
            resolved_subnet_id, require_subnet_preflight = validate_subnet_reference(
                subnet_id
            )
            client = get_session().get_client()
            if require_subnet_preflight:
                verify_subnet_membership(
                    client,
                    vpc_id=vpc_krn,
                    subnet_id=resolved_subnet_id,
                    region=x_region,
                )
            return client.asgV1.create_launch_template(
                template_name=template_name,
                vpc_name=vpc_name,
                vpc_krn=vpc_krn,
                subnet_id=resolved_subnet_id,
                image_krn=image_krn,
                instance_name=instance_name,
                instance_type=instance_type,
                min=min_count,
                max=max_count,
                policy=policy,
                region=x_region,
                security_groups=security_groups,
                sshkey_name=sshkey_name,
                volume_name=volume_name,
                volume_size=_volume_payload(volume_size),
                volume_type=volume_type,
                x_region=x_region,
                extra_headers={"x-region": x_region},
                **drop_none({"user_data": user_data}),
            )

        return run_tool(_run)

    @mcp.tool()
    def update_launch_template(
        template_id: str,
        template_name: str,
        instance_name: Optional[str] = None,
        instance_type: Optional[str] = None,
        sshkey_name: Optional[str] = None,
        image_krn: Optional[str] = None,
        security_groups: Optional[list[str]] = None,
        volume_size: Optional[list[ASGVolume]] = None,
        min_count: Optional[NonNegativeCount] = None,
        max_count: Optional[PositiveCount] = None,
        policy: Optional[list[dict[str, Any]]] = None,
        volume_name: Optional[str] = None,
        volume_type: Optional[str] = None,
        user_data: Optional[str | dict[str, Any]] = None,
        region: ASGMutationRegion = ASG_REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Update an ASG launch template."""

        def _run() -> Any:
            ensure_writable(settings(), "update_launch_template")
            ensure_confirmed(confirm, "update_launch_template", template_id)
            _validate_scaling_bounds(min_count, max_count)
            client = get_session().get_client()
            return sdk_raw_result(
                client.asgV1.with_raw_response.update_launch_template,
                template_id=template_id,
                template_name=template_name,
                extra_headers={"x-region": resolve_region(region)},
                **drop_none(
                    {
                        "instance_name": instance_name,
                        "instance_type": instance_type,
                        "sshkey_name": sshkey_name,
                        "image_krn": image_krn,
                        "security_groups": security_groups,
                        "volume_size": (
                            None if volume_size is None else _volume_payload(volume_size)
                        ),
                        "min": min_count,
                        "max": max_count,
                        "policy": policy,
                        "volume_name": volume_name,
                        "volume_type": volume_type,
                        "user_data": user_data,
                        "x_region": resolve_region(region),
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_launch_template(
        template_id: str,
        template_name: str,
        version: PositiveCount,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Delete an ASG launch template."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_launch_template")
            ensure_confirmed(confirm, "delete_launch_template", template_id)
            client = get_session().get_client()
            return sdk_raw_result(
                client.asgV1.with_raw_response.delete_launch_template,
                template_id=template_id,
                template_name=template_name,
                version=version,
                x_region=resolve_region(region),
            )

        return run_tool(_run)
