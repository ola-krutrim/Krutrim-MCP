"""Direct block-storage adapters for the current KBS wire contracts."""

import re
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx
from krutrim_client import KrutrimClient

from krutrim_mcp_server.adapters._http import required_json_response, response_payload
from krutrim_mcp_server.config import KNOWN_REGIONS

_KBS_SNAPSHOT_PATH = "/kbs/v1/snapshots"
_KBS_BACKUP_PATH = "/kbs/v1/backups"
_KBS_VOLUME_PATH = "/kbs/v1/volumes"
_KBS_VOLUME_TYPES_PATH = f"{_KBS_VOLUME_PATH}/types"
_KBS_INTERNAL_AVAILABILITY_ZONE = "nova"
_KBS_VOLUME_TYPES = frozenset({"HNSS", "HNSS_Encrypted"})
_KBS_VOLUME_SOURCE_TYPES = frozenset({"image", "volume", "snapshot"})
_KBS_COPY_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_KBS_COPY_NAME_FORBIDDEN_SEQUENCES = ("..", "--", ".-", "-.")


def _kbs_headers(*, vpc_krn: str, x_region: str) -> dict[str, str]:
    return {"K-Tenant-ID": vpc_krn, "x-region": x_region}


def _kbs_delete_result(
    response: httpx.Response,
    *,
    resource_type: str,
    resource_id: str,
) -> dict[str, Any]:
    """Normalize a KBS delete without treating acceptance as completion."""
    if response.status_code not in {202, 204}:
        raise ValueError(
            f"{resource_type} delete returned unexpected HTTP {response.status_code}; "
            "expected 204 or 202"
        )
    result: dict[str, Any] = {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "status_code": response.status_code,
    }
    if response.status_code == 202:
        result.update({"accepted": True, "completed": False})
    else:
        result["completed"] = True
    if response.content:
        result["response"] = response_payload(response)
    return result


def _kbs_create_result(response: httpx.Response) -> dict[str, Any]:
    """Normalize a KBS create without treating acceptance as completion."""
    result: dict[str, Any] = {"status_code": response.status_code}
    if response.status_code == 202:
        result.update({"accepted": True, "completed": False})
    if response.content:
        result["response"] = response_payload(response)
    return result


def _kbs_mutation_result(
    response: httpx.Response,
    *,
    operation: str,
    allowed_statuses: frozenset[int],
) -> dict[str, Any]:
    """Normalize a selected KBS mutation without overstating async completion."""
    if response.status_code not in allowed_statuses:
        expected = ", ".join(str(status) for status in sorted(allowed_statuses))
        raise ValueError(
            f"{operation} returned unexpected HTTP {response.status_code}; "
            f"expected one of: {expected}"
        )
    result: dict[str, Any] = {
        "operation": operation,
        "status_code": response.status_code,
    }
    if response.status_code == 202:
        result.update({"accepted": True, "completed": False})
    elif response.status_code == 204:
        result["completed"] = True
    if response.content:
        result["response"] = response_payload(response)
    return result


def _required_kbs_json_collection_or_object(
    response: httpx.Response,
    *,
    operation: str,
) -> dict[str, Any] | list[Any]:
    """Return a verified KBS JSON object or list for a read operation."""
    if response.status_code != 200:
        raise ValueError(
            f"{operation} returned unexpected HTTP {response.status_code}; expected 200"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError(f"{operation} returned a non-JSON response") from exc
    if not isinstance(payload, (dict, list)):
        raise ValueError(
            f"{operation} returned {type(payload).__name__}; expected dict or list"
        )
    return payload


def _validate_kbs_metadata(
    metadata: dict[str, str] | None,
    *,
    operation: str,
) -> dict[str, str] | None:
    if metadata is None:
        return None
    if not isinstance(metadata, dict):
        raise TypeError(f"{operation} metadata must be an object of string values")
    if len(metadata) > 128:
        raise ValueError(f"{operation} metadata cannot contain more than 128 entries")
    normalized: dict[str, str] = {}
    for key, value in metadata.items():
        if (
            not isinstance(key, str)
            or not key
            or key != key.strip()
            or len(key) > 255
            or any(ord(character) < 32 or ord(character) == 127 for character in key)
        ):
            raise ValueError(
                f"{operation} metadata keys must be 1-255 printable characters "
                "without surrounding whitespace"
            )
        if not isinstance(value, str):
            raise TypeError(f"{operation} metadata values must be strings")
        if len(value) > 4096:
            raise ValueError(f"{operation} metadata values cannot exceed 4096 characters")
        normalized[key] = value
    return normalized


def validate_kbs_update_fields(
    *,
    operation: str,
    name: str | None,
    description: str | None,
    metadata: dict[str, str] | None,
) -> tuple[str | None, str | None, dict[str, str] | None]:
    if name is not None and (
        not isinstance(name, str) or not name or name != name.strip()
    ):
        raise ValueError(f"{operation} name must be a nonblank string")
    if description is not None and not isinstance(description, str):
        raise TypeError(f"{operation} description must be a string")
    normalized_metadata = _validate_kbs_metadata(metadata, operation=operation)
    if name is None and description is None and metadata is None:
        raise ValueError(
            f"{operation} requires at least one user-supplied name, description, or metadata"
        )
    return name, description, normalized_metadata


def validate_kbs_policy_request(
    *,
    policy_type: str,
    name: str,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
    maximum_count: int,
    cron: str,
) -> tuple[str, str, str, int, str]:
    if policy_type not in {"snapshot", "backup"}:
        raise ValueError(f"Unsupported KBS policy type: {policy_type!r}")
    if not isinstance(name, str) or not _KBS_COPY_NAME_PATTERN.fullmatch(name):
        raise ValueError(
            "policy name must be 3-63 lowercase letters, digits, dots, or hyphens and "
            "must start and end with a letter or digit"
        )
    if any(sequence in name for sequence in _KBS_COPY_NAME_FORBIDDEN_SEQUENCES):
        raise ValueError("policy name cannot contain adjacent dots or hyphens")
    if type(maximum_count) is not int or maximum_count < 1:
        raise ValueError("policy maximum count must be a positive integer")
    if (
        not isinstance(cron, str)
        or not cron
        or cron != cron.strip()
        or len(cron) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in cron)
    ):
        raise ValueError(
            "cron must be a nonblank printable expression without surrounding whitespace"
        )
    normalized_volume_id, _, normalized_vpc_krn = validate_kbs_volume_reference(
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        copy_type=f"create_volume_{policy_type}_policy",
    )
    return name, normalized_volume_id, normalized_vpc_krn, maximum_count, cron


def validate_kbs_copy_request(
    *,
    copy_type: str,
    name: str,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
    force: bool,
    description: str | None,
) -> tuple[str, str, str, str]:
    """Validate KBS copy identifiers without rewriting them."""
    if not isinstance(name, str) or not _KBS_COPY_NAME_PATTERN.fullmatch(name):
        raise ValueError(
            "name must be 3-63 lowercase letters, digits, dots, or hyphens and "
            "must start and end with a letter or digit"
        )
    if any(sequence in name for sequence in _KBS_COPY_NAME_FORBIDDEN_SEQUENCES):
        raise ValueError("name cannot contain adjacent dots or hyphens")

    volume_id, _, normalized_vpc_krn = validate_kbs_volume_reference(
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        copy_type=copy_type,
    )
    if type(force) is not bool:
        raise TypeError("force must be bool")
    if description is not None and not isinstance(description, str):
        raise TypeError("description must be a string when provided")
    return name, volume_id, normalized_vpc_krn, description or ""


def validate_kbs_volume_reference(
    *,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
    copy_type: str = "copy",
) -> tuple[str, str, str]:
    """Validate a full volume KRN against the owning VPC KRN and region."""
    return validate_kbs_resource_reference(
        resource_id=volume_id,
        resource_type="volume",
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation=copy_type,
    )


def validate_kbs_vpc_reference(
    *,
    vpc_krn: str,
    x_region: str,
    operation: str,
) -> str:
    """Validate the full VPC KRN used as K-Tenant-ID for a KBS request."""
    if not isinstance(vpc_krn, str) or not vpc_krn.strip():
        raise ValueError("vpc_krn must be the full source VPC KRN")
    normalized_vpc_krn = vpc_krn.strip()
    vpc_parts = normalized_vpc_krn.split(":")
    if (
        len(vpc_parts) != 7
        or any(not part for part in vpc_parts)
        or vpc_parts[0] != "krn"
        or vpc_parts[1] != "vpc"
        or vpc_parts[5] != "vpc"
    ):
        raise ValueError("vpc_krn must be the full source VPC KRN")
    if x_region not in KNOWN_REGIONS:
        raise ValueError(f"Unsupported KBS {operation} region: {x_region}")
    if vpc_parts[2] != x_region:
        raise ValueError(
            f"vpc_krn region {vpc_parts[2]!r} does not match selected region "
            f"{x_region!r}"
        )
    return normalized_vpc_krn


def validate_kbs_image_reference(*, image_krn: str, x_region: str) -> str:
    """Validate a full machine-image KRN used as a KBS boot-volume source."""
    if not isinstance(image_krn, str) or not image_krn.strip():
        raise ValueError("image_krn must be a full Krutrim machine-image KRN")
    normalized_image_krn = image_krn.strip()
    image_parts = normalized_image_krn.split(":")
    if (
        len(image_parts) != 7
        or any(not part for part in image_parts)
        or image_parts[0] != "krn"
        or image_parts[1] != "vm"
        or image_parts[5] != "image"
    ):
        raise ValueError("image_krn must be a full Krutrim machine-image KRN")
    if image_parts[2] != x_region:
        raise ValueError(
            f"image_krn region {image_parts[2]!r} does not match selected region "
            f"{x_region!r}"
        )
    try:
        image_uuid = str(UUID(image_parts[6]))
    except ValueError as exc:
        raise ValueError(
            "image_krn must end with a canonical lowercase image UUID"
        ) from exc
    if image_uuid != image_parts[6]:
        raise ValueError("image_krn must end with a canonical lowercase image UUID")
    return normalized_image_krn


def validate_kbs_volume_source_reference(
    *,
    source_type: str | None,
    source_id: str | None,
    vpc_krn: str,
    x_region: str,
) -> tuple[str | None, str | None]:
    """Validate an optional image, volume, or snapshot source for a new volume."""
    if source_type is None and source_id is None:
        return None, None
    if source_type is None or source_id is None:
        raise ValueError("source_type and source_id must be provided together")
    if not isinstance(source_type, str) or source_type not in _KBS_VOLUME_SOURCE_TYPES:
        raise ValueError("source_type must be 'image', 'volume', or 'snapshot'")

    if source_type == "image":
        return source_type, validate_kbs_image_reference(
            image_krn=source_id,
            x_region=x_region,
        )

    normalized_source_id, _, _ = validate_kbs_resource_reference(
        resource_id=source_id,
        resource_type=source_type,
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation="create_volume",
    )
    return source_type, normalized_source_id


def validate_kbs_resource_reference(
    *,
    resource_id: str,
    resource_type: str,
    vpc_krn: str,
    x_region: str,
    operation: str,
) -> tuple[str, str, str]:
    """Validate a full volume/snapshot/backup KRN and its VPC scope."""
    if resource_type not in {"volume", "snapshot", "backup"}:
        raise ValueError(f"Unsupported KBS resource type: {resource_type!r}")
    normalized_vpc_krn = validate_kbs_vpc_reference(
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation=operation,
    )
    vpc_parts = normalized_vpc_krn.split(":")

    invalid_krn_message = (
        "volume_id must be a full Krutrim block-volume KRN"
        if resource_type == "volume"
        else f"{resource_type}_id must be a full Krutrim KBS KRN"
    )
    invalid_uuid_message = (
        "volume_id must end with a canonical lowercase volume UUID"
        if resource_type == "volume"
        else f"{resource_type}_id must end with a canonical lowercase UUID"
    )
    if not isinstance(resource_id, str):
        raise ValueError(invalid_krn_message)
    resource_parts = resource_id.split(":")
    if (
        len(resource_parts) != 7
        or any(not part for part in resource_parts)
        or resource_parts[0] != "krn"
        or resource_parts[1] != "kbs"
        or resource_parts[5] != resource_type
    ):
        raise ValueError(invalid_krn_message)
    try:
        resource_uuid = str(UUID(resource_parts[6]))
    except ValueError as exc:
        raise ValueError(invalid_uuid_message) from exc
    if resource_uuid != resource_parts[6]:
        raise ValueError(invalid_uuid_message)
    if resource_parts[2:5] != vpc_parts[2:5]:
        raise ValueError(
            f"{resource_type}_id KRN region/customer/account scope does not match "
            "vpc_krn"
        )
    return resource_id, resource_uuid, normalized_vpc_krn


def validate_kbs_backup_identifier(
    *,
    backup_id: str,
    vpc_krn: str,
    x_region: str,
    operation: str,
) -> tuple[str, str]:
    """Validate a safe opaque backup path identifier and any embedded KRN scope."""
    normalized_vpc_krn = validate_kbs_vpc_reference(
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation=operation,
    )
    if (
        not isinstance(backup_id, str)
        or not backup_id
        or backup_id != backup_id.strip()
        or backup_id in {".", ".."}
        or len(backup_id) > 512
        or any(character.isspace() for character in backup_id)
        or any(ord(character) < 32 or ord(character) == 127 for character in backup_id)
        or any(character in backup_id for character in "/?#")
    ):
        raise ValueError(
            "backup_id must be the exact nonblank path-safe identifier returned by KBS"
        )
    if backup_id.startswith("krn:"):
        validate_kbs_resource_reference(
            resource_id=backup_id,
            resource_type="backup",
            vpc_krn=normalized_vpc_krn,
            x_region=x_region,
            operation=operation,
        )
    return backup_id, normalized_vpc_krn


def validate_kbs_volume_create_request(
    *,
    name: str,
    size_gb: int,
    vpc_krn: str,
    x_region: str,
    volume_type: str = "HNSS",
    multiattach: bool = False,
    description: str | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
) -> tuple[str, int, str, str, bool, str | None, str | None, str | None]:
    """Validate a blank or source-backed KBS volume request."""
    if not isinstance(name, str) or not name or name != name.strip():
        raise ValueError("name must be a nonblank string without surrounding whitespace")
    if type(size_gb) is not int or size_gb < 1:
        raise ValueError("size_gb must be a positive integer")
    if not isinstance(volume_type, str) or volume_type not in _KBS_VOLUME_TYPES:
        raise ValueError("volume_type must be either 'HNSS' or 'HNSS_Encrypted'")
    if type(multiattach) is not bool:
        raise TypeError("multiattach must be bool")
    if description is not None and not isinstance(description, str):
        raise TypeError("description must be a string when provided")

    normalized_vpc_krn = validate_kbs_vpc_reference(
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation="create_volume",
    )
    normalized_source_type, normalized_source_id = validate_kbs_volume_source_reference(
        source_type=source_type,
        source_id=source_id,
        vpc_krn=normalized_vpc_krn,
        x_region=x_region,
    )
    return (
        name,
        size_gb,
        normalized_vpc_krn,
        volume_type,
        multiattach,
        description,
        normalized_source_type,
        normalized_source_id,
    )


def create_volume(
    client: KrutrimClient,
    *,
    name: str,
    size_gb: int,
    vpc_krn: str,
    x_region: str,
    volume_type: str = "HNSS",
    multiattach: bool = False,
    description: str | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
) -> dict[str, Any]:
    """Create a blank or source-backed KBS volume in the internal ``nova`` zone."""
    (
        name,
        size_gb,
        normalized_vpc_krn,
        volume_type,
        multiattach,
        description,
        normalized_source_type,
        normalized_source_id,
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
    body: dict[str, Any] = {
        "availability_zone": _KBS_INTERNAL_AVAILABILITY_ZONE,
        "name": name,
        "size": size_gb,
        "volumetype": volume_type,
        "multiattach": multiattach,
    }
    if description is not None:
        body["description"] = description
    if normalized_source_type is not None and normalized_source_id is not None:
        body["source"] = {
            "id": normalized_source_id,
            "type": normalized_source_type,
        }

    response = client.post(
        _KBS_VOLUME_PATH,
        cast_to=httpx.Response,
        body=body,
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "max_retries": 0,
        },
    )
    return _kbs_create_result(response)


def create_volume_snapshot(
    client: KrutrimClient,
    *,
    name: str,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
    force: bool = False,
    description: str | None = None,
) -> dict[str, Any]:
    """Create a point-in-time KBS snapshot for one explicit source volume."""
    name, volume_id, vpc_krn, description = validate_kbs_copy_request(
        copy_type="snapshot",
        name=name,
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        force=force,
        description=description,
    )
    response = client.post(
        _KBS_SNAPSHOT_PATH,
        cast_to=httpx.Response,
        body={
            "name": name,
            "description": description,
            "volume_id": volume_id,
            "force": force,
        },
        options={
            "headers": {
                "K-Tenant-ID": vpc_krn,
                "x-region": x_region,
            }
        },
    )
    return response_payload(response)


def create_volume_backup(
    client: KrutrimClient,
    *,
    name: str,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
    force: bool = False,
    description: str | None = None,
) -> dict[str, Any]:
    """Create one non-incremental KBS backup for an explicit source volume."""
    name, volume_id, vpc_krn, description = validate_kbs_copy_request(
        copy_type="backup",
        name=name,
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        force=force,
        description=description,
    )
    response = client.post(
        _KBS_BACKUP_PATH,
        cast_to=httpx.Response,
        body={
            "name": name,
            "description": description,
            "volume_id": volume_id,
            "force": force,
            "incremental": False,
        },
        options={
            "headers": {
                "K-Tenant-ID": vpc_krn,
                "x-region": x_region,
            }
        },
    )
    return response_payload(response)


def update_volume_snapshot(
    client: KrutrimClient,
    *,
    snapshot_id: str,
    vpc_krn: str,
    x_region: str,
    name: str | None = None,
    description: str | None = None,
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Update user-supplied fields on one exact KBS snapshot."""
    snapshot_id, _, normalized_vpc_krn = validate_kbs_resource_reference(
        resource_id=snapshot_id,
        resource_type="snapshot",
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation="update_volume_snapshot",
    )
    name, description, metadata = validate_kbs_update_fields(
        operation="update_volume_snapshot",
        name=name,
        description=description,
        metadata=metadata,
    )
    body: dict[str, Any] = {}
    if name is not None:
        body["name"] = name
    if description is not None:
        body["description"] = description
    if metadata is not None:
        body["metadata"] = metadata
    response = client.put(
        f"{_KBS_SNAPSHOT_PATH}/{quote(snapshot_id, safe=':')}",
        cast_to=httpx.Response,
        body=body,
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "max_retries": 0,
        },
    )
    return _kbs_mutation_result(
        response,
        operation="update_volume_snapshot",
        allowed_statuses=frozenset({200, 202}),
    )


def _create_volume_policy(
    client: KrutrimClient,
    *,
    policy_type: str,
    name: str,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
    maximum_count: int,
    cron: str,
) -> dict[str, Any]:
    name, volume_id, normalized_vpc_krn, maximum_count, cron = (
        validate_kbs_policy_request(
            policy_type=policy_type,
            name=name,
            volume_id=volume_id,
            vpc_krn=vpc_krn,
            x_region=x_region,
            maximum_count=maximum_count,
            cron=cron,
        )
    )
    collection = "snapshots" if policy_type == "snapshot" else "backups"
    count_field = (
        "max_snapshots_allowed"
        if policy_type == "snapshot"
        else "max_backups_allowed"
    )
    response = client.post(
        f"{_KBS_VOLUME_PATH}/{quote(volume_id, safe=':')}/{collection}/policy",
        cast_to=httpx.Response,
        body={"name": name, count_field: maximum_count, "cron": cron},
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "max_retries": 0,
        },
    )
    return _kbs_mutation_result(
        response,
        operation=f"create_volume_{policy_type}_policy",
        allowed_statuses=frozenset({200, 201, 202}),
    )


def create_volume_snapshot_policy(
    client: KrutrimClient,
    *,
    name: str,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
    max_snapshots_allowed: int,
    cron: str,
) -> dict[str, Any]:
    """Create the snapshot-retention policy attached to one exact KBS volume."""
    return _create_volume_policy(
        client,
        policy_type="snapshot",
        name=name,
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        maximum_count=max_snapshots_allowed,
        cron=cron,
    )


def create_volume_backup_policy(
    client: KrutrimClient,
    *,
    name: str,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
    max_backups_allowed: int,
    cron: str,
) -> dict[str, Any]:
    """Create the backup-retention policy attached to one exact KBS volume."""
    return _create_volume_policy(
        client,
        policy_type="backup",
        name=name,
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        maximum_count=max_backups_allowed,
        cron=cron,
    )


def _delete_volume_policy(
    client: KrutrimClient,
    *,
    policy_type: str,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    if policy_type not in {"snapshot", "backup"}:
        raise ValueError(f"Unsupported KBS policy type: {policy_type!r}")
    volume_id, _, normalized_vpc_krn = validate_kbs_volume_reference(
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        copy_type=f"delete_volume_{policy_type}_policy",
    )
    collection = "snapshots" if policy_type == "snapshot" else "backups"
    response = client.delete(
        f"{_KBS_VOLUME_PATH}/{quote(volume_id, safe=':')}/{collection}/policy",
        cast_to=httpx.Response,
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "max_retries": 0,
        },
    )
    return _kbs_mutation_result(
        response,
        operation=f"delete_volume_{policy_type}_policy",
        allowed_statuses=frozenset({200, 202, 204}),
    )


def delete_volume_snapshot_policy(
    client: KrutrimClient,
    *,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Delete the snapshot policy attached to one exact KBS volume."""
    return _delete_volume_policy(
        client,
        policy_type="snapshot",
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
    )


def delete_volume_backup_policy(
    client: KrutrimClient,
    *,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Delete the backup policy attached to one exact KBS volume."""
    return _delete_volume_policy(
        client,
        policy_type="backup",
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
    )


def restore_volume_backup(
    client: KrutrimClient,
    *,
    backup_id: str,
    name: str,
    vpc_krn: str,
    x_region: str,
    target_volume_id: str | None = None,
) -> dict[str, Any]:
    """Restore a KBS backup into a new or explicit existing volume."""
    backup_id, normalized_vpc_krn = validate_kbs_backup_identifier(
        backup_id=backup_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation="restore_volume_backup",
    )
    if not isinstance(name, str) or not _KBS_COPY_NAME_PATTERN.fullmatch(name):
        raise ValueError(
            "restore name must be 3-63 lowercase letters, digits, dots, or hyphens and "
            "must start and end with a letter or digit"
        )
    if any(sequence in name for sequence in _KBS_COPY_NAME_FORBIDDEN_SEQUENCES):
        raise ValueError("restore name cannot contain adjacent dots or hyphens")
    normalized_target_volume_id: str | None = None
    if target_volume_id is not None:
        normalized_target_volume_id, _, _ = validate_kbs_volume_reference(
            volume_id=target_volume_id,
            vpc_krn=normalized_vpc_krn,
            x_region=x_region,
            copy_type="restore_volume_backup",
        )
    body: dict[str, Any] = {"name": name}
    if normalized_target_volume_id is not None:
        body["volume_id"] = normalized_target_volume_id
    response = client.post(
        f"{_KBS_BACKUP_PATH}/{quote(backup_id, safe=':')}/restore",
        cast_to=httpx.Response,
        body=body,
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "max_retries": 0,
        },
    )
    return _kbs_mutation_result(
        response,
        operation="restore_volume_backup",
        allowed_statuses=frozenset({200, 201, 202}),
    )


def extend_volume(
    client: KrutrimClient,
    *,
    volume_id: str,
    new_size_gb: int,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Increase one exact KBS volume to the requested total GiB size."""
    volume_id, _, normalized_vpc_krn = validate_kbs_volume_reference(
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        copy_type="extend_volume",
    )
    if type(new_size_gb) is not int or new_size_gb < 1:
        raise ValueError("new_size_gb must be a positive integer")
    response = client.post(
        f"{_KBS_VOLUME_PATH}/{quote(volume_id, safe=':')}/action",
        cast_to=httpx.Response,
        body={"input": {"newSize": new_size_gb}},
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "params": {"op": "extend"},
            "max_retries": 0,
        },
    )
    return _kbs_mutation_result(
        response,
        operation="extend_volume",
        allowed_statuses=frozenset({201, 202, 204}),
    )


def update_volume(
    client: KrutrimClient,
    *,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
    name: str | None = None,
    description: str | None = None,
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Update user-supplied descriptive fields on one exact KBS volume."""
    volume_id, _, normalized_vpc_krn = validate_kbs_volume_reference(
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        copy_type="update_volume",
    )
    name, description, metadata = validate_kbs_update_fields(
        operation="update_volume",
        name=name,
        description=description,
        metadata=metadata,
    )
    fields: dict[str, Any] = {}
    if name is not None:
        fields["name"] = name
    if description is not None:
        fields["description"] = description
    if metadata is not None:
        fields["metadata"] = metadata
    response = client.put(
        f"{_KBS_VOLUME_PATH}/{quote(volume_id, safe=':')}",
        cast_to=httpx.Response,
        body={"volume": fields},
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "max_retries": 0,
        },
    )
    return _kbs_mutation_result(
        response,
        operation="update_volume",
        allowed_statuses=frozenset({200, 202}),
    )


def list_volume_types(
    client: KrutrimClient,
    *,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any] | list[Any]:
    """List volume types visible to one explicit VPC and region."""
    normalized_vpc_krn = validate_kbs_vpc_reference(
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation="list_volume_types",
    )
    response = client.get(
        _KBS_VOLUME_TYPES_PATH,
        cast_to=httpx.Response,
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            )
        },
    )
    return _required_kbs_json_collection_or_object(
        response,
        operation="list_volume_types",
    )


def change_volume_type(
    client: KrutrimClient,
    *,
    volume_id: str,
    volume_type: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Change one exact KBS volume to a supported volume type."""
    volume_id, _, normalized_vpc_krn = validate_kbs_volume_reference(
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        copy_type="change_volume_type",
    )
    if volume_type not in _KBS_VOLUME_TYPES:
        raise ValueError("volume_type must be either 'HNSS' or 'HNSS_Encrypted'")
    response = client.put(
        f"{_KBS_VOLUME_PATH}/{quote(volume_id, safe=':')}/change_type",
        cast_to=httpx.Response,
        body={"volume_type": volume_type},
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "max_retries": 0,
        },
    )
    return _kbs_mutation_result(
        response,
        operation="change_volume_type",
        allowed_statuses=frozenset({200, 202, 204}),
    )


def force_delete_volume(
    client: KrutrimClient,
    *,
    volume_id: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Force-delete one exact KBS volume with retries disabled."""
    volume_id, _, normalized_vpc_krn = validate_kbs_volume_reference(
        volume_id=volume_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        copy_type="force_delete_volume",
    )
    response = client.delete(
        f"{_KBS_VOLUME_PATH}/{quote(volume_id, safe=':')}",
        cast_to=httpx.Response,
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "params": {"force": True},
            "max_retries": 0,
        },
    )
    return _kbs_mutation_result(
        response,
        operation="force_delete_volume",
        allowed_statuses=frozenset({200, 202, 204}),
    )


def _list_kbs_collection(
    client: KrutrimClient,
    *,
    path: str,
    operation: str,
    vpc_krn: str,
    x_region: str,
) -> list[Any]:
    normalized_vpc_krn = validate_kbs_vpc_reference(
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation=operation,
    )
    response = client.get(
        path,
        cast_to=httpx.Response,
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            )
        },
    )
    return required_json_response(
        response,
        expected_type=list,
        operation=operation,
    )


def _get_kbs_resource(
    client: KrutrimClient,
    *,
    path: str,
    operation: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    normalized_vpc_krn = validate_kbs_vpc_reference(
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation=operation,
    )
    response = client.get(
        path,
        cast_to=httpx.Response,
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            )
        },
    )
    return required_json_response(
        response,
        expected_type=dict,
        operation=operation,
    )


def _delete_kbs_resource(
    client: KrutrimClient,
    *,
    path: str,
    operation: str,
    resource_type: str,
    resource_id: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    normalized_vpc_krn = validate_kbs_vpc_reference(
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation=operation,
    )
    response = client.delete(
        path,
        cast_to=httpx.Response,
        options={
            "headers": _kbs_headers(
                vpc_krn=normalized_vpc_krn,
                x_region=x_region,
            ),
            "max_retries": 0,
        },
    )
    return _kbs_delete_result(
        response,
        resource_type=resource_type,
        resource_id=resource_id,
    )


def list_volumes(
    client: KrutrimClient,
    *,
    vpc_krn: str,
    x_region: str,
) -> list[Any]:
    """List the unpaginated KBS volume collection for one VPC and region."""
    return _list_kbs_collection(
        client,
        path=_KBS_VOLUME_PATH,
        operation="list_volumes",
        vpc_krn=vpc_krn,
        x_region=x_region,
    )


def list_volume_snapshots(
    client: KrutrimClient,
    *,
    vpc_krn: str,
    x_region: str,
) -> list[Any]:
    """List the unpaginated KBS snapshot collection for one VPC and region."""
    return _list_kbs_collection(
        client,
        path=_KBS_SNAPSHOT_PATH,
        operation="list_volume_snapshots",
        vpc_krn=vpc_krn,
        x_region=x_region,
    )


def retrieve_volume_snapshot(
    client: KrutrimClient,
    *,
    snapshot_id: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Retrieve one KBS snapshot by its full KRN."""
    snapshot_id, _, normalized_vpc_krn = validate_kbs_resource_reference(
        resource_id=snapshot_id,
        resource_type="snapshot",
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation="retrieve_volume_snapshot",
    )
    return _get_kbs_resource(
        client,
        path=f"{_KBS_SNAPSHOT_PATH}/{quote(snapshot_id, safe=':')}",
        operation="retrieve_volume_snapshot",
        vpc_krn=normalized_vpc_krn,
        x_region=x_region,
    )


def delete_volume_snapshot(
    client: KrutrimClient,
    *,
    snapshot_id: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Delete one KBS snapshot by its full KRN."""
    snapshot_id, _, normalized_vpc_krn = validate_kbs_resource_reference(
        resource_id=snapshot_id,
        resource_type="snapshot",
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation="delete_volume_snapshot",
    )
    return _delete_kbs_resource(
        client,
        path=f"{_KBS_SNAPSHOT_PATH}/{quote(snapshot_id, safe=':')}",
        operation="delete_volume_snapshot",
        resource_type="volume_snapshot",
        resource_id=snapshot_id,
        vpc_krn=normalized_vpc_krn,
        x_region=x_region,
    )


def list_volume_backups(
    client: KrutrimClient,
    *,
    vpc_krn: str,
    x_region: str,
) -> list[Any]:
    """List the unpaginated KBS backup collection for one VPC and region."""
    return _list_kbs_collection(
        client,
        path=_KBS_BACKUP_PATH,
        operation="list_volume_backups",
        vpc_krn=vpc_krn,
        x_region=x_region,
    )


def retrieve_volume_backup(
    client: KrutrimClient,
    *,
    backup_id: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Retrieve one KBS backup by its exact API identifier."""
    backup_id, normalized_vpc_krn = validate_kbs_backup_identifier(
        backup_id=backup_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation="retrieve_volume_backup",
    )
    return _get_kbs_resource(
        client,
        path=f"{_KBS_BACKUP_PATH}/{quote(backup_id, safe=':')}",
        operation="retrieve_volume_backup",
        vpc_krn=normalized_vpc_krn,
        x_region=x_region,
    )


def delete_volume_backup(
    client: KrutrimClient,
    *,
    backup_id: str,
    vpc_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Delete one KBS backup by its exact API identifier."""
    backup_id, normalized_vpc_krn = validate_kbs_backup_identifier(
        backup_id=backup_id,
        vpc_krn=vpc_krn,
        x_region=x_region,
        operation="delete_volume_backup",
    )
    return _delete_kbs_resource(
        client,
        path=f"{_KBS_BACKUP_PATH}/{quote(backup_id, safe=':')}",
        operation="delete_volume_backup",
        resource_type="volume_backup",
        resource_id=backup_id,
        vpc_krn=normalized_vpc_krn,
        x_region=x_region,
    )
