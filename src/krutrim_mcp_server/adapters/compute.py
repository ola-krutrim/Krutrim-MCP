"""Direct compute API adapters for verified SDK contract gaps."""

import re
from collections.abc import Mapping
from typing import Any

import httpx
from krutrim_client import KrutrimClient

from krutrim_mcp_server.adapters._http import required_json_response, response_payload
from krutrim_mcp_server.config import KNOWN_REGIONS

_DELETE_INSTANCE_PATH = "/vm/v1/delete_instance_async"
_COMPUTE_FLAVOR_PATH = "/api/v1/flavor/compute"
_COMPUTE_FLAVOR_TYPE = "CPU"
_GPU_FLAVOR_TYPE = "GPU"
_COMPUTE_FLAVOR_TYPES = frozenset({_COMPUTE_FLAVOR_TYPE, _GPU_FLAVOR_TYPE})


def _normalize_compute_flavor(
    group_by: Mapping[str, Any],
    *,
    index: int,
    flavor_type: str,
) -> dict[str, Any]:
    required_fields = {
        "flavorid",
        "flavorname",
        "cpus",
        "cpuram",
        "flavorstatus",
    }
    missing_fields = sorted(required_fields - set(group_by))
    if missing_fields:
        raise ValueError(
            f"list_compute_flavors returned a matching {flavor_type} entry "
            f"at index {index} without required fields: {', '.join(missing_fields)}"
        )

    flavor_id = group_by["flavorid"]
    if not isinstance(flavor_id, str) or not flavor_id.strip():
        raise ValueError(
            f"list_compute_flavors returned a matching {flavor_type} entry "
            f"at index {index} with an invalid groupBy.flavorid"
        )

    string_fields = {
        "flavorname": "name",
        "flavorstatus": "status",
    }
    normalized_strings: dict[str, str] = {}
    for source, target in string_fields.items():
        value = group_by[source]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"list_compute_flavors returned a matching {flavor_type} entry "
                f"at index {index} with an invalid groupBy.{source}"
            )
        normalized_strings[target] = value

    optional_metadata_fields = {
        "cost": "cost",
        "currency": "currency",
        "unit": "unit",
    }
    normalized_metadata: dict[str, str | None] = {}
    for source, target in optional_metadata_fields.items():
        value = group_by.get(source)
        if value is None:
            normalized_metadata[target] = None
        elif isinstance(value, str):
            normalized_metadata[target] = value.strip() or None
        elif isinstance(value, int | float | bool):
            normalized_metadata[target] = str(value)
        else:
            raise ValueError(
                f"list_compute_flavors returned a matching {flavor_type} entry "
                f"at index {index} with an invalid groupBy.{source}"
            )

    positive_integer_fields = {"cpus": "vcpus", "cpuram": "memory_gb"}
    normalized_integers: dict[str, int] = {}
    for source, target in positive_integer_fields.items():
        value = group_by[source]
        if type(value) is int:
            normalized_value = value
        elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
            normalized_value = int(value, 10)
        else:
            raise ValueError(
                f"list_compute_flavors returned a matching {flavor_type} entry "
                f"at index {index} with an invalid groupBy.{source}; expected a positive "
                "integer or base-10 digit string"
            )
        if normalized_value < 1:
            raise ValueError(
                f"list_compute_flavors returned a matching {flavor_type} entry "
                f"at index {index} with an invalid groupBy.{source}; expected a positive "
                "integer or base-10 digit string"
            )
        normalized_integers[target] = normalized_value

    status = normalized_strings["status"]
    return {
        "id": flavor_id,
        "name": normalized_strings["name"],
        "vcpus": normalized_integers["vcpus"],
        "memory_gb": normalized_integers["memory_gb"],
        "cost": normalized_metadata["cost"],
        "currency": normalized_metadata["currency"],
        "unit": normalized_metadata["unit"],
        "status": status,
        "selectable": status.lower() == "active",
    }


def list_compute_flavors(
    client: KrutrimClient,
    *,
    x_region: str,
    flavor_type: str = _COMPUTE_FLAVOR_TYPE,
) -> dict[str, Any]:
    """List the verified regional compute flavor catalog used by VM creation."""
    requested_flavor_type = flavor_type
    if x_region not in KNOWN_REGIONS:
        raise ValueError(
            f"Unsupported compute flavor region {x_region!r}; expected one of: "
            f"{', '.join(KNOWN_REGIONS)}"
        )
    if requested_flavor_type not in _COMPUTE_FLAVOR_TYPES:
        raise ValueError(
            f"Unsupported compute flavor type {requested_flavor_type!r}; expected one of: "
            f"{', '.join(sorted(_COMPUTE_FLAVOR_TYPES))}"
        )

    response = client.get(
        _COMPUTE_FLAVOR_PATH,
        cast_to=httpx.Response,
        options={
            "headers": {"x-region": x_region},
            "params": {"type": requested_flavor_type},
        },
    )
    payload = required_json_response(
        response,
        expected_type=list,
        operation="list_compute_flavors",
    )

    flavors: list[dict[str, Any]] = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, Mapping):
            raise ValueError(
                "list_compute_flavors returned an invalid entry object "
                f"at index {index}"
            )
        subject = entry.get("subject")
        if not isinstance(subject, str) or not subject.strip():
            raise ValueError(
                "list_compute_flavors returned an entry "
                f"at index {index} with an invalid subject"
            )
        group_by = entry.get("groupBy")
        if not isinstance(group_by, Mapping):
            raise ValueError(
                "list_compute_flavors returned an entry "
                f"at index {index} with an invalid groupBy object"
            )
        entry_flavor_type = group_by.get("type")
        if not isinstance(entry_flavor_type, str) or not entry_flavor_type.strip():
            raise ValueError(
                "list_compute_flavors returned an entry "
                f"at index {index} with an invalid groupBy.type"
            )
        if subject != x_region or entry_flavor_type != requested_flavor_type:
            continue
        flavors.append(
            _normalize_compute_flavor(
                group_by,
                index=index,
                flavor_type=requested_flavor_type,
            )
        )

    flavors.sort(key=lambda flavor: (flavor["vcpus"], flavor["memory_gb"], flavor["name"]))
    return {
        "region": x_region,
        "flavor_type": requested_flavor_type,
        "selection_required": True,
        "flavors": flavors,
    }


def validate_compute_flavor_name(
    client: KrutrimClient,
    *,
    flavor_name: str,
    x_region: str,
    flavor_type: str = _COMPUTE_FLAVOR_TYPE,
) -> str:
    """Require one exact, case-sensitive active flavor name without a fallback."""
    if not isinstance(flavor_name, str) or not flavor_name.strip():
        raise ValueError(
            f"instance_type must be a non-empty exact {flavor_type} flavor name"
        )

    catalog = list_compute_flavors(
        client,
        x_region=x_region,
        flavor_type=flavor_type,
    )
    active_names = sorted(
        {flavor["name"] for flavor in catalog["flavors"] if flavor["selectable"] is True}
    )
    if flavor_name in active_names:
        return flavor_name

    choices = ", ".join(active_names) if active_names else "none currently available"
    raise ValueError(
        f"instance_type {flavor_name!r} is not an active {flavor_type} flavor in region "
        f"{x_region!r}. Choose one exact case-sensitive active name from: {choices}. "
        "No default or fallback flavor was applied."
    )


def delete_instance_async(
    client: KrutrimClient,
    *,
    instance_krn: str | None,
    delete_volume: bool,
    x_region: str,
    task_id: str | None = None,
) -> dict[str, Any]:
    """Delete a VM through the async endpoint, including failed-create task IDs."""
    normalized_instance_krn = ""
    if instance_krn is not None:
        if not isinstance(instance_krn, str):
            raise ValueError("instance_krn must be a string when provided")
        normalized_instance_krn = instance_krn.strip()
    if type(delete_volume) is not bool:
        raise TypeError("delete_volume must be bool")
    if x_region not in KNOWN_REGIONS:
        raise ValueError(f"Unsupported instance delete region: {x_region}")
    if not normalized_instance_krn and not task_id:
        raise ValueError("instance_krn is required unless task_id is provided")

    normalized_task_id: str | None = None
    if task_id is not None:
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("task_id must be a non-empty string when provided")
        normalized_task_id = task_id.strip()

    options: dict[str, Any] = {
        "headers": {"x-region": x_region},
        "max_retries": 0,
    }
    if normalized_instance_krn:
        params: dict[str, Any] = {
            "instanceKrn": normalized_instance_krn,
            "deleteVolume": delete_volume,
        }
        if normalized_task_id is not None:
            params["task_id"] = normalized_task_id
        options["params"] = params
    else:
        options["params"] = {
            "deleteVolume": delete_volume,
            "task_id": normalized_task_id,
        }

    response = client.delete(
        _DELETE_INSTANCE_PATH,
        cast_to=httpx.Response,
        options=options,
    )
    return response_payload(response)
