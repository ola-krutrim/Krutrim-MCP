"""Block storage and object storage (KOS) MCP tools."""

import re
from collections.abc import Mapping
from typing import Annotated, Any, Literal, Optional
from uuid import UUID

from pydantic import Field

from krutrim_mcp_server.adapters.kbs import (
    change_volume_type as change_kbs_volume_type,
)
from krutrim_mcp_server.adapters.kbs import (
    create_volume as create_kbs_volume,
)
from krutrim_mcp_server.adapters.kbs import (
    create_volume_backup as create_kbs_volume_backup,
)
from krutrim_mcp_server.adapters.kbs import (
    create_volume_backup_policy as create_kbs_volume_backup_policy,
)
from krutrim_mcp_server.adapters.kbs import (
    create_volume_snapshot as create_kbs_volume_snapshot,
)
from krutrim_mcp_server.adapters.kbs import (
    create_volume_snapshot_policy as create_kbs_volume_snapshot_policy,
)
from krutrim_mcp_server.adapters.kbs import (
    delete_volume_backup as delete_kbs_volume_backup,
)
from krutrim_mcp_server.adapters.kbs import (
    delete_volume_backup_policy as delete_kbs_volume_backup_policy,
)
from krutrim_mcp_server.adapters.kbs import (
    delete_volume_snapshot as delete_kbs_volume_snapshot,
)
from krutrim_mcp_server.adapters.kbs import (
    delete_volume_snapshot_policy as delete_kbs_volume_snapshot_policy,
)
from krutrim_mcp_server.adapters.kbs import extend_volume as extend_kbs_volume
from krutrim_mcp_server.adapters.kbs import (
    force_delete_volume as force_delete_kbs_volume,
)
from krutrim_mcp_server.adapters.kbs import (
    list_volume_backups as list_kbs_volume_backups,
)
from krutrim_mcp_server.adapters.kbs import (
    list_volume_snapshots as list_kbs_volume_snapshots,
)
from krutrim_mcp_server.adapters.kbs import (
    list_volume_types as list_kbs_volume_types,
)
from krutrim_mcp_server.adapters.kbs import (
    restore_volume_backup as restore_kbs_volume_backup,
)
from krutrim_mcp_server.adapters.kbs import (
    retrieve_volume_backup as retrieve_kbs_volume_backup,
)
from krutrim_mcp_server.adapters.kbs import (
    retrieve_volume_snapshot as retrieve_kbs_volume_snapshot,
)
from krutrim_mcp_server.adapters.kbs import update_volume as update_kbs_volume
from krutrim_mcp_server.adapters.kbs import (
    update_volume_snapshot as update_kbs_volume_snapshot,
)
from krutrim_mcp_server.adapters.kbs import (
    validate_kbs_backup_identifier,
    validate_kbs_copy_request,
    validate_kbs_policy_request,
    validate_kbs_resource_reference,
    validate_kbs_update_fields,
    validate_kbs_volume_create_request,
    validate_kbs_volume_reference,
    validate_kbs_vpc_reference,
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
from krutrim_mcp_server.tools.storage.kos_routing import (
    KOS_TIERS,
    response_value,
    storage_tier_for_region,
)

PositiveSize = Annotated[int, Field(ge=1)]
NonEmptyIdentifier = Annotated[str, Field(min_length=1)]
CronExpression = Annotated[
    str,
    Field(
        min_length=1,
        max_length=256,
        description="Exact KBS cron expression explicitly supplied by the user.",
    ),
]
MetadataMap = Annotated[
    dict[str, str],
    Field(
        max_length=128,
        description="Complete metadata object explicitly supplied for this update.",
    ),
]
CopyName = Annotated[
    str,
    Field(
        min_length=3,
        max_length=63,
        pattern=r"^[a-z0-9](?:[a-z0-9]|[.-][a-z0-9])*$",
        description=(
            "Unique 3-63 character lowercase name using letters, digits, dots, or "
            "hyphens. Adjacent punctuation is rejected. Use the same name to reconcile "
            "an uncertain timeout before retrying."
        ),
    ),
]
VolumeKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^krn:kbs:(?:In-Bangalore-1|In-Hyderabad-1):[^:]+:[^:]+:volume:"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
        description=(
            "Full KRN of the one source block-storage volume. Use describe_volume's "
            "krn field, or its id only when that id is itself a full krn:kbs value; "
            "do not pass a bare UUID."
        ),
    ),
]
VpcKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^krn:vpc:(?:In-Bangalore-1|In-Hyderabad-1):"
            r"[^:]+:[^:]+:vpc:[^:]+$"
        ),
        description=(
            "Full KRN of the VPC that owns the source volume; sent as K-Tenant-ID."
        ),
    ),
]
VolumeSourceType = Literal["image", "volume", "snapshot"]
VolumeSourceKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^(?:krn:vm:(?:In-Bangalore-1|In-Hyderabad-1):"
            r"[^:]+:[^:]+:image:"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
            r"|krn:kbs:(?:In-Bangalore-1|In-Hyderabad-1):"
            r"[^:]+:[^:]+:(?:volume|snapshot):"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
        ),
        description=(
            "Full KRN matching source_type: machine image, KBS volume, or KBS "
            "snapshot. KBS sources must share the selected VPC scope."
        ),
    ),
]
SnapshotKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^krn:kbs:(?:In-Bangalore-1|In-Hyderabad-1):[^:]+:[^:]+:snapshot:"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
        description="Full snapshot KRN copied exactly from list_volume_snapshots.",
    ),
]
BackupIdentifier = Annotated[
    str,
    Field(
        min_length=1,
        max_length=512,
        pattern=r"^[^\s/?#]+$",
        description=(
            "Exact path-safe backup id copied unchanged from list_volume_backups."
        ),
    ),
]
InstanceKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^krn:vm:(?:In-Bangalore-1|In-Hyderabad-1):[^:]+:[^:]+:instance:"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
        description="Full VM instance KRN copied from describe_instance.",
    ),
]
AttachmentIdentifier = Annotated[
    str,
    Field(
        min_length=1,
        max_length=512,
        pattern=r"^[^\s/?#]+$",
        description=(
            "Exact remote_attachment_id copied from describe_volume's attachments list."
        ),
    ),
]
MountPartition = Annotated[
    str,
    Field(
        min_length=6,
        max_length=64,
        pattern=r"^/dev/[A-Za-z0-9._-]+$",
        description="Guest device path requested for the attached volume.",
    ),
]


def _preflight_bucket_tier(
    client: Any,
    *,
    bucket_krn: str,
    region: str,
) -> str:
    inventory = _list_bucket_inventory(client)
    buckets = (
        inventory if isinstance(inventory, (list, tuple)) else response_value(inventory, "items")
    )
    if not isinstance(buckets, (list, tuple)):
        raise ValueError(
            "object-storage bucket inventory returned an invalid response; operation blocked"
        )

    matches = [
        bucket
        for bucket in buckets
        if bucket_krn
        in {
            response_value(bucket, "krnid"),
            response_value(bucket, "krn"),
            response_value(bucket, "id"),
        }
    ]
    if len(matches) != 1:
        raise ValueError(
            "object-storage bucket preflight did not return exactly the requested bucket; "
            "operation blocked"
        )

    bucket = matches[0]
    bucket_region = response_value(bucket, "region")
    if bucket_region != region:
        raise ValueError(
            f"object-storage bucket belongs to region {bucket_region!r}, not selected region "
            f"{region!r}; operation blocked"
        )

    tier = response_value(bucket, "tier")
    if tier not in KOS_TIERS:
        raise ValueError(
            "object-storage bucket preflight did not return a supported tier; operation blocked"
        )
    return tier


def _list_bucket_inventory(client: Any) -> Any:
    # krutrim-client 0.5.x declares a list, while the live API wraps it in `items`.
    return client.get("/kos/v1/buckets", cast_to=object)


def _volume_field(volume: Any, field: str) -> Any:
    if isinstance(volume, Mapping):
        return volume.get(field)
    return getattr(volume, field, None)


def _require_exact_resource_identity(
    payload: Mapping[str, Any],
    *,
    expected_id: str,
    resource_type: str,
) -> None:
    actual_id = payload.get("id")
    if actual_id != expected_id:
        raise ValueError(
            f"KBS {resource_type} preflight did not return the requested id; "
            "operation blocked"
        )


def _authoritative_volume_krn(
    volume: Any,
    *,
    vpc_krn: str,
    region: str,
) -> str:
    authoritative_ids: list[str] = []
    for field in ("id", "krn"):
        candidate = _volume_field(volume, field)
        if isinstance(candidate, str) and candidate.startswith("krn:"):
            authoritative_id, _, _ = validate_kbs_volume_reference(
                volume_id=candidate,
                vpc_krn=vpc_krn,
                x_region=region,
            )
            authoritative_ids.append(authoritative_id)
    if not authoritative_ids:
        raise ValueError(
            "KBS source preflight returned no authoritative full volume KRN; "
            "creation blocked"
        )
    if len(set(authoritative_ids)) != 1:
        raise ValueError(
            "KBS source preflight returned conflicting volume KRNs; creation blocked"
        )
    return authoritative_ids[0]


def _validate_instance_krn(instance_id: str, *, region: str) -> str:
    if not isinstance(instance_id, str) or not instance_id.strip():
        raise ValueError("instance_id must be a non-empty full VM instance KRN")
    normalized = instance_id.strip()
    parts = normalized.split(":")
    if (
        len(parts) != 7
        or any(not part for part in parts)
        or parts[0] != "krn"
        or parts[1] != "vm"
        or parts[5] != "instance"
    ):
        raise ValueError("instance_id must be a full Krutrim VM instance KRN")
    if parts[2] != region:
        raise ValueError(
            f"instance_id region {parts[2]!r} does not match selected region {region!r}"
        )
    try:
        instance_uuid = str(UUID(parts[6]))
    except ValueError as exc:
        raise ValueError("instance_id must end with a canonical lowercase instance UUID") from exc
    if instance_uuid != parts[6]:
        raise ValueError("instance_id must end with a canonical lowercase instance UUID")
    return normalized


def _validate_mount_partition(mount_partition: str) -> str:
    if (
        not isinstance(mount_partition, str)
        or not re.fullmatch(r"/dev/[A-Za-z0-9._-]+", mount_partition)
        or len(mount_partition) > 64
    ):
        raise ValueError("mount_partition must be a valid /dev/... guest device path")
    return mount_partition


def _same_resource_reference(candidate: Any, expected_krn: str) -> bool:
    if not isinstance(candidate, str) or not candidate.strip():
        return False
    value = candidate.strip()
    return value == expected_krn or value == expected_krn.rsplit(":", 1)[-1]


def _preflight_kbs_instance(
    client: Any,
    *,
    instance_id: str,
    vpc_krn: str,
    region: str,
) -> Any:
    instance = client.highlvlvpc.retrieve_instance(krn=instance_id, x_region=region)
    if _volume_field(instance, "krn") != instance_id:
        raise ValueError(
            "instance identity preflight did not return the exact requested KRN; "
            "operation blocked"
        )
    vpc_references = (
        _volume_field(instance, "project_krn"),
        _volume_field(instance, "vpc_id"),
    )
    if not any(_same_resource_reference(value, vpc_krn) for value in vpc_references):
        raise ValueError(
            "instance preflight did not place the VM in the selected VPC; operation blocked"
        )
    return instance


def _preflight_kbs_volume(
    client: Any,
    *,
    volume_id: str,
    vpc_krn: str,
    region: str,
) -> Any:
    volume = client.kbs.retrieve_volume(
        volume_id,
        k_tenant_id=vpc_krn,
        x_region=region,
    )
    authoritative_id = _authoritative_volume_krn(
        volume,
        vpc_krn=vpc_krn,
        region=region,
    )
    if authoritative_id != volume_id:
        raise ValueError(
            "volume identity preflight did not return the exact requested KRN; "
            "operation blocked"
        )
    return volume


def _volume_attachments(volume: Any) -> list[Any]:
    attachments = _volume_field(volume, "attachments")
    if attachments is None:
        return []
    if not isinstance(attachments, (list, tuple)):
        raise ValueError("volume preflight returned an invalid attachments field")
    return list(attachments)


def _volume_attachment_state(volume: Any) -> bool:
    attachments = _volume_field(volume, "attachments")
    if isinstance(attachments, (list, tuple)):
        if attachments:
            return True
    elif attachments is not None:
        raise ValueError("volume preflight returned an invalid attachments field")

    states = {
        str(value).strip().lower()
        for value in (
            _volume_field(volume, "status"),
            _volume_field(volume, "state"),
        )
        if isinstance(value, str) and value.strip()
    }
    if states.intersection({"attached", "in-use", "in_use"}):
        return True
    if states.intersection({"available", "success"}):
        return False
    if isinstance(attachments, (list, tuple)):
        return False
    raise ValueError(
        "volume preflight could not verify attachment state; operation blocked"
    )


def _require_detached_volume(volume: Any, *, operation: str) -> None:
    if _volume_attachment_state(volume):
        raise ValueError(f"{operation} requires a detached volume; operation blocked")


def _require_failed_volume(volume: Any, *, operation: str) -> None:
    raw_status = _volume_field(volume, "status")
    raw_state = _volume_field(volume, "state")
    status = raw_status.strip().lower() if isinstance(raw_status, str) else ""
    state = raw_state.strip().lower() if isinstance(raw_state, str) else ""
    lifecycle_status = status or state
    failed_statuses = {"error", "failed", "failure"}
    failed_prefixes = ("error_", "error-", "failed_", "failed-")

    if not lifecycle_status:
        raise ValueError(
            f"{operation} could not verify a failed volume status; operation blocked"
        )
    if lifecycle_status not in failed_statuses and not lifecycle_status.startswith(
        failed_prefixes
    ):
        raise ValueError(
            f"{operation} requires a failed volume status; observed "
            f"{lifecycle_status!r}; operation blocked"
        )


def _require_attached_volume_acknowledgement(
    volume: Any,
    *,
    operation: str,
    allow_attached_volume: bool,
) -> None:
    if type(allow_attached_volume) is not bool:
        raise TypeError("allow_attached_volume must be bool")
    if _volume_attachment_state(volume) and not allow_attached_volume:
        raise ValueError(
            f"{operation} targets an attached volume; set allow_attached_volume=true "
            "only after the user explicitly accepts the risk"
        )


def _current_volume_size_gb(volume: Any) -> int:
    for field in ("size", "size_gb", "Size"):
        value = _volume_field(volume, field)
        if type(value) is int and value > 0:
            return value
        if isinstance(value, str) and value.isdigit() and int(value) > 0:
            return int(value)
    raise ValueError("volume preflight returned no verifiable positive size")


def _current_volume_type(volume: Any) -> str | None:
    for field in ("volume_type", "volumetype", "VolumeType"):
        value = _volume_field(volume, field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _preflight_volume_attach_state(
    volume: Any,
    *,
    instance_id: str,
    allow_multiattach: bool,
) -> None:
    attachments = _volume_attachments(volume)
    if any(
        _same_resource_reference(_volume_field(item, "instance_id"), instance_id)
        for item in attachments
    ):
        raise ValueError("volume is already attached to the requested instance")

    if attachments:
        multiattach = _volume_field(volume, "multiattach")
        if multiattach is None:
            multiattach = _volume_field(volume, "multi_attached_enabled")
        if not allow_multiattach:
            raise ValueError(
                "volume is already attached; set allow_multiattach=true only after the user "
                "explicitly confirms another attachment"
            )
        if multiattach is not True:
            raise ValueError("volume does not report multiattach capability")
        return

    states = {
        str(value).strip().lower()
        for value in (
            _volume_field(volume, "status"),
            _volume_field(volume, "state"),
        )
        if isinstance(value, str) and value.strip()
    }
    if not states:
        raise ValueError(
            "volume preflight did not return a verifiable attachment state; operation blocked"
        )
    if not states.intersection({"available", "success"}):
        raise ValueError(
            "volume is not in an attachable available state; operation blocked"
        )


def _preflight_volume_detach_attachment(
    volume: Any,
    *,
    instance_id: str,
    attachment_id: str,
) -> None:
    matches = [
        item
        for item in _volume_attachments(volume)
        if _same_resource_reference(_volume_field(item, "instance_id"), instance_id)
        and _volume_field(item, "remote_attachment_id") == attachment_id
    ]
    if len(matches) != 1:
        raise ValueError(
            "volume attachment preflight did not return the exact instance and attachment id; "
            "operation blocked"
        )


def _preflight_kbs_volume_create_source(
    client: Any,
    *,
    source_type: str | None,
    source_id: str | None,
    vpc_krn: str,
    region: str,
) -> None:
    """Verify a KBS clone/restore source under the selected VPC before POST."""
    if source_type is None or source_type == "image":
        return
    if source_id is None:
        raise ValueError("source_type and source_id must be provided together")

    if source_type == "volume":
        volume = client.kbs.retrieve_volume(
            source_id,
            k_tenant_id=vpc_krn,
            x_region=region,
        )
        authoritative_id = _authoritative_volume_krn(
            volume,
            vpc_krn=vpc_krn,
            region=region,
        )
        if authoritative_id != source_id:
            raise ValueError(
                "KBS source preflight did not return the requested volume KRN; "
                "creation blocked"
            )
        return

    snapshot = retrieve_kbs_volume_snapshot(
        client,
        snapshot_id=source_id,
        vpc_krn=vpc_krn,
        x_region=region,
    )
    authoritative_ids: list[str] = []
    for field in ("id", "krn"):
        candidate = snapshot.get(field)
        if isinstance(candidate, str) and candidate.startswith("krn:"):
            authoritative_id, _, _ = validate_kbs_resource_reference(
                resource_id=candidate,
                resource_type="snapshot",
                vpc_krn=vpc_krn,
                x_region=region,
                operation="create_volume",
            )
            authoritative_ids.append(authoritative_id)
    if not authoritative_ids or set(authoritative_ids) != {source_id}:
        raise ValueError(
            "KBS source preflight did not return the requested snapshot KRN; "
            "creation blocked"
        )


def _preflight_kbs_copy_source(
    client: Any,
    *,
    volume_id: str,
    vpc_krn: str,
    region: str,
    allow_attached_volume: bool,
) -> tuple[str, bool]:
    """Verify source identity and SDK attachment data before a billed POST."""
    volume = client.kbs.retrieve_volume(
        volume_id,
        k_tenant_id=vpc_krn,
        x_region=region,
    )
    authoritative_id = _authoritative_volume_krn(
        volume,
        vpc_krn=vpc_krn,
        region=region,
    )
    if authoritative_id != volume_id:
        raise ValueError(
            "KBS source preflight did not return the requested volume KRN; creation blocked"
        )

    attachments = _volume_field(volume, "attachments")
    raw_status = _volume_field(volume, "status")
    raw_state = _volume_field(volume, "state")
    status = raw_status.strip().lower() if isinstance(raw_status, str) else ""
    state = raw_state.strip().lower() if isinstance(raw_state, str) else ""
    attached_states = {"attached", "in-use", "in_use"}
    attached_hint = status in attached_states or state in attached_states
    ready_hint = status in {"available", "success"} or state == "available"

    if isinstance(attachments, (list, tuple)):
        if attachments or attached_hint:
            attached = True
        elif ready_hint:
            attached = False
        else:
            raise ValueError(
                "KBS source preflight could not verify volume readiness; creation blocked"
            )
    elif attachments is None and state == "available" and status in {
        "available",
        "success",
    }:
        attached = False
    elif attachments is None and attached_hint:
        attached = True
    else:
        raise ValueError(
            "KBS source preflight could not verify volume attachment state; creation blocked"
        )

    if attached and not allow_attached_volume:
        raise ValueError(
            "source volume is attached; set allow_attached_volume=true only after the "
            "user explicitly accepts crash/application-consistency risk"
        )
    return authoritative_id, attached


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_buckets() -> str:
        """List object storage (KOS) buckets for the account."""

        def _run() -> Any:
            client = get_session().get_client()
            return _list_bucket_inventory(client)

        return run_tool(_run)

    @mcp.tool()
    def create_bucket(
        name: str,
        region: Region = REGION_FIELD,
        description: Optional[str] = None,
        anonymous_access: bool = False,
        allow_public_access: bool = False,
        versioning: bool = False,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create an object storage bucket."""

        def _run() -> Any:
            ensure_writable(settings(), "create_bucket")
            ensure_confirmed(confirm, "create_bucket", name)
            if anonymous_access and not allow_public_access:
                raise ValueError(
                    "anonymous_access=true requires allow_public_access=true after explicit "
                    "user approval"
                )
            x_region = resolve_region(region)
            tier = storage_tier_for_region(x_region)
            client = get_session().get_client()
            kwargs: dict[str, Any] = {
                "name": name,
                "region": x_region,
                "x_region_id": x_region,
                "anonymous_access": anonymous_access,
                "versioning": versioning,
                "extra_headers": {"x-tier": tier},
                "extra_body": {"tier": tier},
            }
            if description is not None:
                kwargs["description"] = description
            return client.kos.buckets.create_bucket(**kwargs)

        return run_tool(_run)

    @mcp.tool()
    def delete_bucket(
        bucket_krn: NonEmptyIdentifier,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """Delete an object-storage bucket by KRN."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_bucket")
            ensure_confirmed(confirm, "delete_bucket", bucket_krn)
            x_region = resolve_region(region)
            client = get_session().get_client()
            tier = _preflight_bucket_tier(
                client,
                bucket_krn=bucket_krn,
                region=x_region,
            )
            return client.kos.buckets.delete_bucket(
                bucket_krn,
                x_region_id=x_region,
                extra_headers={"x-tier": tier},
            )

        return run_tool(_run)

    @mcp.tool()
    def list_storage_access_keys() -> str:
        """List object storage access keys."""

        def _run() -> Any:
            client = get_session().get_client()
            return client.kos.accessKeys.list()

        return run_tool(_run)

    @mcp.tool()
    def list_volumes(
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
    ) -> str:
        """List the KBS volume collection for one explicit VPC and region."""

        def _run() -> Any:
            x_region = resolve_region(region)
            validated_vpc_krn = validate_kbs_vpc_reference(
                vpc_krn=vpc_krn,
                x_region=x_region,
                operation="list_volumes",
            )
            client = get_session().get_client()
            return client.kbs.list_volumes(
                k_tenant_id=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def list_volume_types(
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
    ) -> str:
        """List KBS volume types available to one explicit VPC and region."""

        def _run() -> Any:
            x_region = resolve_region(region)
            validated_vpc_krn = validate_kbs_vpc_reference(
                vpc_krn=vpc_krn,
                x_region=x_region,
                operation="list_volume_types",
            )
            return list_kbs_volume_types(
                get_session().get_client(),
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def list_volume_snapshots(
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
    ) -> str:
        """List the KBS volume-snapshot collection for one VPC and region."""

        def _run() -> Any:
            x_region = resolve_region(region)
            validated_vpc_krn = validate_kbs_vpc_reference(
                vpc_krn=vpc_krn,
                x_region=x_region,
                operation="list_volume_snapshots",
            )
            client = get_session().get_client()
            return list_kbs_volume_snapshots(
                client,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def describe_volume_snapshot(
        snapshot_id: SnapshotKrn,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
    ) -> str:
        """Describe one KBS volume snapshot by its full snapshot KRN."""

        def _run() -> Any:
            x_region = resolve_region(region)
            validated_snapshot_id, _, validated_vpc_krn = (
                validate_kbs_resource_reference(
                    resource_id=snapshot_id,
                    resource_type="snapshot",
                    vpc_krn=vpc_krn,
                    x_region=x_region,
                    operation="describe_volume_snapshot",
                )
            )
            client = get_session().get_client()
            return retrieve_kbs_volume_snapshot(
                client,
                snapshot_id=validated_snapshot_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def update_volume_snapshot(
        snapshot_id: SnapshotKrn,
        vpc_krn: VpcKrn,
        name: Optional[NonEmptyIdentifier] = None,
        description: Optional[str] = None,
        metadata: Optional[MetadataMap] = None,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Update only the snapshot fields explicitly supplied by the user."""

        def _run() -> Any:
            ensure_writable(settings(), "update_volume_snapshot")
            ensure_confirmed(confirm, "update_volume_snapshot", snapshot_id)
            x_region = resolve_region(region)
            validated_snapshot_id, _, validated_vpc_krn = (
                validate_kbs_resource_reference(
                    resource_id=snapshot_id,
                    resource_type="snapshot",
                    vpc_krn=vpc_krn,
                    x_region=x_region,
                    operation="update_volume_snapshot",
                )
            )
            validated_name, validated_description, validated_metadata = (
                validate_kbs_update_fields(
                    operation="update_volume_snapshot",
                    name=name,
                    description=description,
                    metadata=metadata,
                )
            )
            client = get_session().get_client()
            snapshot = retrieve_kbs_volume_snapshot(
                client,
                snapshot_id=validated_snapshot_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )
            _require_exact_resource_identity(
                snapshot,
                expected_id=validated_snapshot_id,
                resource_type="snapshot",
            )
            return update_kbs_volume_snapshot(
                client,
                snapshot_id=validated_snapshot_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
                name=validated_name,
                description=validated_description,
                metadata=validated_metadata,
            )

        return run_tool(_run)

    @mcp.tool()
    def list_volume_backups(
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
    ) -> str:
        """List the KBS volume-backup collection for one VPC and region."""

        def _run() -> Any:
            x_region = resolve_region(region)
            validated_vpc_krn = validate_kbs_vpc_reference(
                vpc_krn=vpc_krn,
                x_region=x_region,
                operation="list_volume_backups",
            )
            client = get_session().get_client()
            return list_kbs_volume_backups(
                client,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def describe_volume_backup(
        backup_id: BackupIdentifier,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
    ) -> str:
        """Describe one KBS volume backup by its exact API identifier."""

        def _run() -> Any:
            x_region = resolve_region(region)
            validated_backup_id, validated_vpc_krn = validate_kbs_backup_identifier(
                backup_id=backup_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                operation="describe_volume_backup",
            )
            client = get_session().get_client()
            return retrieve_kbs_volume_backup(
                client,
                backup_id=validated_backup_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def restore_volume_backup(
        backup_id: BackupIdentifier,
        name: CopyName,
        vpc_krn: VpcKrn,
        target_volume_id: Optional[VolumeKrn] = None,
        allow_target_volume_overwrite: bool = False,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Restore one exact backup into a new or explicitly approved existing volume."""

        def _run() -> Any:
            ensure_writable(settings(), "restore_volume_backup")
            ensure_confirmed(confirm, "restore_volume_backup", backup_id)
            x_region = resolve_region(region)
            validated_backup_id, validated_vpc_krn = validate_kbs_backup_identifier(
                backup_id=backup_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                operation="restore_volume_backup",
            )
            validated_target_volume_id: str | None = None
            if target_volume_id is None:
                if allow_target_volume_overwrite:
                    raise ValueError(
                        "allow_target_volume_overwrite=true requires target_volume_id"
                    )
            else:
                if not allow_target_volume_overwrite:
                    raise ValueError(
                        "target_volume_id requires allow_target_volume_overwrite=true "
                        "after explicit user approval"
                    )
                validated_target_volume_id, _, _ = validate_kbs_volume_reference(
                    volume_id=target_volume_id,
                    vpc_krn=validated_vpc_krn,
                    x_region=x_region,
                    copy_type="restore_volume_backup",
                )

            client = get_session().get_client()
            backup = retrieve_kbs_volume_backup(
                client,
                backup_id=validated_backup_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )
            _require_exact_resource_identity(
                backup,
                expected_id=validated_backup_id,
                resource_type="backup",
            )
            if validated_target_volume_id is not None:
                target = _preflight_kbs_volume(
                    client,
                    volume_id=validated_target_volume_id,
                    vpc_krn=validated_vpc_krn,
                    region=x_region,
                )
                _require_detached_volume(target, operation="restore_volume_backup")
            return restore_kbs_volume_backup(
                client,
                backup_id=validated_backup_id,
                name=name,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
                target_volume_id=validated_target_volume_id,
            )

        return run_tool(_run)

    @mcp.tool()
    def describe_volume(
        volume_id: str,
        tenant_id: str,
        region: Region = REGION_FIELD,
    ) -> str:
        """Describe a block storage volume"""

        def _run() -> Any:
            client = get_session().get_client()
            return client.kbs.retrieve_volume(
                volume_id,
                k_tenant_id=tenant_id,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def update_volume(
        volume_id: VolumeKrn,
        vpc_krn: VpcKrn,
        name: Optional[NonEmptyIdentifier] = None,
        description: Optional[str] = None,
        metadata: Optional[MetadataMap] = None,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Update only the volume fields explicitly supplied by the user."""

        def _run() -> Any:
            ensure_writable(settings(), "update_volume")
            ensure_confirmed(confirm, "update_volume", volume_id)
            x_region = resolve_region(region)
            validated_volume_id, _, validated_vpc_krn = validate_kbs_volume_reference(
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                copy_type="update_volume",
            )
            validated_name, validated_description, validated_metadata = (
                validate_kbs_update_fields(
                    operation="update_volume",
                    name=name,
                    description=description,
                    metadata=metadata,
                )
            )
            client = get_session().get_client()
            _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            return update_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
                name=validated_name,
                description=validated_description,
                metadata=validated_metadata,
            )

        return run_tool(_run)

    @mcp.tool()
    def extend_volume(
        volume_id: VolumeKrn,
        new_size_gb: PositiveSize,
        vpc_krn: VpcKrn,
        allow_attached_volume: bool = False,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Increase a volume to an explicit total GiB size; shrinking is blocked."""

        def _run() -> Any:
            ensure_writable(settings(), "extend_volume")
            ensure_confirmed(
                confirm,
                "extend_volume",
                f"{volume_id} to {new_size_gb} GiB",
            )
            x_region = resolve_region(region)
            validated_volume_id, _, validated_vpc_krn = validate_kbs_volume_reference(
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                copy_type="extend_volume",
            )
            client = get_session().get_client()
            volume = _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            current_size_gb = _current_volume_size_gb(volume)
            if new_size_gb <= current_size_gb:
                raise ValueError(
                    f"new_size_gb must be greater than current size {current_size_gb} GiB"
                )
            _require_attached_volume_acknowledgement(
                volume,
                operation="extend_volume",
                allow_attached_volume=allow_attached_volume,
            )
            return extend_kbs_volume(
                client,
                volume_id=validated_volume_id,
                new_size_gb=new_size_gb,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def change_volume_type(
        volume_id: VolumeKrn,
        volume_type: VolumeType,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Change a detached volume to an explicitly selected supported type."""

        def _run() -> Any:
            ensure_writable(settings(), "change_volume_type")
            ensure_confirmed(
                confirm,
                "change_volume_type",
                f"{volume_id} to {volume_type}",
            )
            x_region = resolve_region(region)
            validated_volume_id, _, validated_vpc_krn = validate_kbs_volume_reference(
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                copy_type="change_volume_type",
            )
            client = get_session().get_client()
            volume = _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            _require_detached_volume(volume, operation="change_volume_type")
            if _current_volume_type(volume) == volume_type:
                raise ValueError("volume already has the requested volume_type")
            return change_kbs_volume_type(
                client,
                volume_id=validated_volume_id,
                volume_type=volume_type,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def attach_volume(
        volume_id: VolumeKrn,
        instance_id: InstanceKrn,
        vpc_krn: VpcKrn,
        mount_partition: MountPartition = "/dev/vdz",
        allow_multiattach: bool = False,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Attach one exact block-storage volume to one exact VM
        """

        def _run() -> Any:
            ensure_writable(settings(), "attach_volume")
            ensure_confirmed(
                confirm,
                "attach_volume",
                f"{volume_id} to {instance_id} at {mount_partition}",
            )
            x_region = resolve_region(region)
            validated_volume_id, _, validated_vpc_krn = validate_kbs_volume_reference(
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                copy_type="attach_volume",
            )
            validated_instance_id = _validate_instance_krn(instance_id, region=x_region)
            validated_mount_partition = _validate_mount_partition(mount_partition)
            if type(allow_multiattach) is not bool:
                raise TypeError("allow_multiattach must be bool")

            client = get_session().get_client()
            _preflight_kbs_instance(
                client,
                instance_id=validated_instance_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            volume = _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            _preflight_volume_attach_state(
                volume,
                instance_id=validated_instance_id,
                allow_multiattach=allow_multiattach,
            )
            return client.kbs.attach_volume(
                validated_volume_id,
                instance_id=validated_instance_id,
                k_tenant_id=validated_vpc_krn,
                x_region=x_region,
                mount_partition=validated_mount_partition,
            )

        return run_tool(_run)

    @mcp.tool()
    def detach_volume(
        volume_id: VolumeKrn,
        instance_id: InstanceKrn,
        attachment_id: AttachmentIdentifier,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Detach one exact volume attachment from a VM
        """

        def _run() -> Any:
            ensure_writable(settings(), "detach_volume")
            ensure_confirmed(
                confirm,
                "detach_volume",
                f"{volume_id} attachment {attachment_id} from {instance_id}",
            )
            x_region = resolve_region(region)
            validated_volume_id, _, validated_vpc_krn = validate_kbs_volume_reference(
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                copy_type="detach_volume",
            )
            validated_instance_id = _validate_instance_krn(instance_id, region=x_region)
            if (
                not isinstance(attachment_id, str)
                or not re.fullmatch(r"[^\s/?#]+", attachment_id)
                or len(attachment_id) > 512
            ):
                raise ValueError("attachment_id must be a path-safe exact attachment id")
            validated_attachment_id = attachment_id.strip()

            client = get_session().get_client()
            _preflight_kbs_instance(
                client,
                instance_id=validated_instance_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            volume = _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            _preflight_volume_detach_attachment(
                volume,
                instance_id=validated_instance_id,
                attachment_id=validated_attachment_id,
            )
            return client.kbs.detach_volume(
                validated_volume_id,
                instance_id=validated_instance_id,
                attachment_id=validated_attachment_id,
                k_tenant_id=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_volume(
        name: NonEmptyIdentifier,
        size_gb: PositiveSize,
        vpc_krn: VpcKrn,
        source_type: Optional[VolumeSourceType] = None,
        source_id: Optional[VolumeSourceKrn] = None,
        volume_type: VolumeType = "HNSS",
        multiattach: bool = False,
        region: Region = REGION_FIELD,
        description: Optional[str] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """
        Create a billable block-storage volume in an explicit VPC and region
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_volume")
            ensure_confirmed(
                confirm,
                "create_volume",
                (
                    f"{name} ({size_gb} GiB {volume_type}) in {vpc_krn}"
                    + (
                        f" from {source_type} {source_id}"
                        if source_type is not None or source_id is not None
                        else ""
                    )
                ),
            )
            x_region = resolve_region(region)
            (
                validated_name,
                validated_size_gb,
                validated_vpc_krn,
                validated_volume_type,
                validated_multiattach,
                validated_description,
                validated_source_type,
                validated_source_id,
            ) = validate_kbs_volume_create_request(
                name=name,
                size_gb=size_gb,
                vpc_krn=vpc_krn,
                x_region=x_region,
                volume_type=volume_type,
                multiattach=multiattach,
                description=description,
                source_type=source_type,
                source_id=source_id,
            )
            client = get_session().get_client()
            _preflight_kbs_volume_create_source(
                client,
                source_type=validated_source_type,
                source_id=validated_source_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            return create_kbs_volume(
                client,
                name=validated_name,
                size_gb=validated_size_gb,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
                volume_type=validated_volume_type,
                multiattach=validated_multiattach,
                description=validated_description,
                source_type=validated_source_type,
                source_id=validated_source_id,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_volume_snapshot(
        name: CopyName,
        volume_id: VolumeKrn,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
        description: Optional[str] = None,
        allow_attached_volume: bool = False,
    ) -> str:
        """
        Create a billable, retained, non-idempotent volume snapshot
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_volume_snapshot")
            ensure_confirmed(
                confirm,
                "create_volume_snapshot",
                f"{name} from volume {volume_id}",
            )
            x_region = resolve_region(region)
            validated_name, validated_volume_id, validated_vpc_krn, validated_description = (
                validate_kbs_copy_request(
                    copy_type="snapshot",
                    name=name,
                    volume_id=volume_id,
                    vpc_krn=vpc_krn,
                    x_region=x_region,
                    force=False,
                    description=description,
                )
            )
            client = get_session().get_client()
            authoritative_volume_id, source_attached = _preflight_kbs_copy_source(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
                allow_attached_volume=allow_attached_volume,
            )
            return create_kbs_volume_snapshot(
                client,
                name=validated_name,
                volume_id=authoritative_volume_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
                force=source_attached,
                description=validated_description,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_volume_backup(
        name: CopyName,
        volume_id: VolumeKrn,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
        description: Optional[str] = None,
        allow_attached_volume: bool = False,
    ) -> str:
        """
        Create a billable, retained, non-idempotent primary volume backup
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_volume_backup")
            ensure_confirmed(
                confirm,
                "create_volume_backup",
                f"primary {name} from volume {volume_id}",
            )
            x_region = resolve_region(region)
            validated_name, validated_volume_id, validated_vpc_krn, validated_description = (
                validate_kbs_copy_request(
                    copy_type="backup",
                    name=name,
                    volume_id=volume_id,
                    vpc_krn=vpc_krn,
                    x_region=x_region,
                    force=False,
                    description=description,
                )
            )
            client = get_session().get_client()
            authoritative_volume_id, source_attached = _preflight_kbs_copy_source(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
                allow_attached_volume=allow_attached_volume,
            )
            return create_kbs_volume_backup(
                client,
                name=validated_name,
                volume_id=authoritative_volume_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
                force=source_attached,
                description=validated_description,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_volume_snapshot_policy(
        name: CopyName,
        volume_id: VolumeKrn,
        max_snapshots_allowed: PositiveSize,
        cron: CronExpression,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a snapshot-retention policy for one exact KBS volume."""

        def _run() -> Any:
            ensure_writable(settings(), "create_volume_snapshot_policy")
            ensure_confirmed(
                confirm,
                "create_volume_snapshot_policy",
                f"{name} on {volume_id}",
            )
            x_region = resolve_region(region)
            (
                validated_name,
                validated_volume_id,
                validated_vpc_krn,
                validated_max_snapshots,
                validated_cron,
            ) = validate_kbs_policy_request(
                policy_type="snapshot",
                name=name,
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                maximum_count=max_snapshots_allowed,
                cron=cron,
            )
            client = get_session().get_client()
            _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            return create_kbs_volume_snapshot_policy(
                client,
                name=validated_name,
                volume_id=validated_volume_id,
                max_snapshots_allowed=validated_max_snapshots,
                cron=validated_cron,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_volume_snapshot_policy(
        volume_id: VolumeKrn,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Delete the snapshot policy attached to one exact KBS volume."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_volume_snapshot_policy")
            ensure_confirmed(confirm, "delete_volume_snapshot_policy", volume_id)
            x_region = resolve_region(region)
            validated_volume_id, _, validated_vpc_krn = validate_kbs_volume_reference(
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                copy_type="delete_volume_snapshot_policy",
            )
            client = get_session().get_client()
            _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            return delete_kbs_volume_snapshot_policy(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_volume_backup_policy(
        name: CopyName,
        volume_id: VolumeKrn,
        max_backups_allowed: PositiveSize,
        cron: CronExpression,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a backup-retention policy for one exact KBS volume."""

        def _run() -> Any:
            ensure_writable(settings(), "create_volume_backup_policy")
            ensure_confirmed(
                confirm,
                "create_volume_backup_policy",
                f"{name} on {volume_id}",
            )
            x_region = resolve_region(region)
            (
                validated_name,
                validated_volume_id,
                validated_vpc_krn,
                validated_max_backups,
                validated_cron,
            ) = validate_kbs_policy_request(
                policy_type="backup",
                name=name,
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                maximum_count=max_backups_allowed,
                cron=cron,
            )
            client = get_session().get_client()
            _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            return create_kbs_volume_backup_policy(
                client,
                name=validated_name,
                volume_id=validated_volume_id,
                max_backups_allowed=validated_max_backups,
                cron=validated_cron,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_volume_backup_policy(
        volume_id: VolumeKrn,
        vpc_krn: VpcKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Delete the backup policy attached to one exact KBS volume."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_volume_backup_policy")
            ensure_confirmed(confirm, "delete_volume_backup_policy", volume_id)
            x_region = resolve_region(region)
            validated_volume_id, _, validated_vpc_krn = validate_kbs_volume_reference(
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                copy_type="delete_volume_backup_policy",
            )
            client = get_session().get_client()
            _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            return delete_kbs_volume_backup_policy(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_volume_snapshot(
        snapshot_id: SnapshotKrn,
        vpc_krn: VpcKrn,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """
        Delete a volume snapshot after exact identity preflight.

        The full snapshot KRN, owning VPC KRN, and region must match. The request
        is not retried.
        """

        def _run() -> Any:
            ensure_writable(settings(), "delete_volume_snapshot")
            ensure_confirmed(confirm, "delete_volume_snapshot", snapshot_id)
            x_region = resolve_region(region)
            validated_snapshot_id, _, validated_vpc_krn = (
                validate_kbs_resource_reference(
                    resource_id=snapshot_id,
                    resource_type="snapshot",
                    vpc_krn=vpc_krn,
                    x_region=x_region,
                    operation="delete_volume_snapshot",
                )
            )
            client = get_session().get_client()
            snapshot = retrieve_kbs_volume_snapshot(
                client,
                snapshot_id=validated_snapshot_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )
            _require_exact_resource_identity(
                snapshot,
                expected_id=validated_snapshot_id,
                resource_type="snapshot",
            )
            return delete_kbs_volume_snapshot(
                client,
                snapshot_id=validated_snapshot_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_volume_backup(
        backup_id: BackupIdentifier,
        vpc_krn: VpcKrn,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """
        Delete an eligible volume backup after exact ID preflight
        """

        def _run() -> Any:
            ensure_writable(settings(), "delete_volume_backup")
            ensure_confirmed(confirm, "delete_volume_backup", backup_id)
            x_region = resolve_region(region)
            validated_backup_id, validated_vpc_krn = validate_kbs_backup_identifier(
                backup_id=backup_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                operation="delete_volume_backup",
            )
            client = get_session().get_client()
            backup = retrieve_kbs_volume_backup(
                client,
                backup_id=validated_backup_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )
            _require_exact_resource_identity(
                backup,
                expected_id=validated_backup_id,
                resource_type="backup",
            )
            return delete_kbs_volume_backup(
                client,
                backup_id=validated_backup_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def force_delete_volume(
        volume_id: VolumeKrn,
        vpc_krn: VpcKrn,
        allow_attached_volume: bool = False,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Force-delete one exact failed KBS volume after risk acknowledgement."""

        def _run() -> Any:
            ensure_writable(settings(), "force_delete_volume")
            ensure_confirmed(confirm, "force_delete_volume", volume_id)
            x_region = resolve_region(region)
            validated_volume_id, _, validated_vpc_krn = validate_kbs_volume_reference(
                volume_id=volume_id,
                vpc_krn=vpc_krn,
                x_region=x_region,
                copy_type="force_delete_volume",
            )
            client = get_session().get_client()
            volume = _preflight_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                region=x_region,
            )
            _require_failed_volume(volume, operation="force_delete_volume")
            _require_attached_volume_acknowledgement(
                volume,
                operation="force_delete_volume",
                allow_attached_volume=allow_attached_volume,
            )
            return force_delete_kbs_volume(
                client,
                volume_id=validated_volume_id,
                vpc_krn=validated_vpc_krn,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_volume(
        volume_id: str,
        tenant_id: str,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """Delete a block-storage volume."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_volume")
            ensure_confirmed(confirm, "delete_volume", volume_id)
            client = get_session().get_client()
            client.kbs.delete_volume(
                volume_id,
                k_tenant_id=tenant_id,
                x_region=resolve_region(region),
            )
            return {"deleted": True, "volume_id": volume_id}

        return run_tool(_run)

    @mcp.tool()
    def plan_delete(
        resource_type: str,
        resource_id: str,
        region: Region = REGION_FIELD,
    ) -> str:
        """
        Preview the identifiers a delete tool would target
        """

        def _run() -> Any:
            return {
                "preview_only": True,
                "dependency_checked": False,
                "operation": f"delete_{resource_type}",
                "resource_type": resource_type,
                "resource_id": resource_id,
                "region": resolve_region(region),
                "next_step": (
                    f"Call delete_{resource_type} with the same id and confirm=true "
                    "only after separately verifying the resource and dependencies."
                ),
                "read_only_mode": settings().read_only,
            }

        return run_tool(_run)
