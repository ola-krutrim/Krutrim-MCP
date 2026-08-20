"""Direct KPod API adapters for verified SDK contract gaps."""

import math
from collections.abc import Mapping
from typing import Any

import httpx
from krutrim_client import KrutrimClient

from krutrim_mcp_server.adapters._http import required_json_response

_KPOD_TEMPLATE_PATH = "/v1/kpod/podtemplate"
_KPOD_FLAVOR_PATH = "/api/v1/flavor/kpod"
_KPOD_GPU_RESOURCE_PATH = "/v2/kpod/gpuresource"
_STRING_FIELDS = {
    "template_container_image_path": "container_image_path",
    "template_container_start_command": "container_start_command",
    "container_disk_size": "container_disk_size",
    "volume_disk_size": "volume_disk_size",
    "volume_mount_path": "volume_mount_path",
    "expose_http_ports": "expose_http_ports",
    "expose_tcp_ports": "expose_tcp_ports",
}
_BOOLEAN_FIELDS = {
    "enable_jupyter": "has_jupyter_notebook",
    "enable_ssh": "has_ssh_access",
}

_SELECTABLE_AVAILABILITY = frozenset({"available", "high", "medium", "low"})


def _required_string(
    entry: Mapping[str, Any],
    field_name: str,
    *,
    operation: str,
    index: int,
) -> str:
    value = entry.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{operation} returned an entry at index {index} with an invalid {field_name}"
        )
    return value.strip()


def _required_number(
    entry: Mapping[str, Any],
    field_name: str,
    *,
    operation: str,
    index: int,
) -> int | float:
    value = entry.get(field_name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(
            f"{operation} returned an entry at index {index} with an invalid {field_name}"
        )
    if not math.isfinite(value) or value < 0:
        raise ValueError(
            f"{operation} returned an entry at index {index} with an invalid {field_name}"
        )
    return value


def _normalize_availability_maps(payload: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}
    for family in ("a100", "h100"):
        raw_mapping = payload.get(family)
        if not isinstance(raw_mapping, Mapping):
            raise ValueError(
                f"list_kpod_flavors returned an invalid GPU availability mapping for {family}"
            )
        family_mapping: dict[str, str] = {}
        for raw_key, raw_value in raw_mapping.items():
            if not isinstance(raw_key, str) or not raw_key.strip():
                raise ValueError(
                    f"list_kpod_flavors returned an invalid GPU availability key for {family}"
                )
            if not isinstance(raw_value, str) or not raw_value.strip():
                raise ValueError(
                    f"list_kpod_flavors returned an invalid GPU availability value for {family}"
                )
            family_mapping[raw_key.strip().casefold()] = raw_value.strip()
        normalized[family] = family_mapping
    return normalized


def _normalize_flavor(
    entry: Mapping[str, Any],
    *,
    index: int,
    availability_maps: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    operation = "list_kpod_flavors"
    group_by = entry.get("groupBy")
    if not isinstance(group_by, Mapping):
        raise ValueError(f"{operation} returned an entry at index {index} with an invalid groupBy")

    flavor_id = _required_string(group_by, "flavorid", operation=operation, index=index)
    flavor_name = _required_string(group_by, "flavorname", operation=operation, index=index)
    status = _required_string(group_by, "flavorstatus", operation=operation, index=index)
    unit = _required_string(group_by, "unit", operation=operation, index=index)
    cost = _required_number(group_by, "cost", operation=operation, index=index)
    gpu_count = _required_number(group_by, "request_gpu_number", operation=operation, index=index)
    ram_gb = _required_number(group_by, "ram_size", operation=operation, index=index)
    vcpus = _required_number(group_by, "vcpu_num", operation=operation, index=index)
    gpu_memory_gb = _required_number(group_by, "gpu_ram_size", operation=operation, index=index)

    folded_id = flavor_id.casefold()
    if "h100" in folded_id:
        family = "h100"
    elif "a100" in folded_id:
        family = "a100"
    else:
        family = "unknown"

    availability = "Unknown"
    availability_key: str | None = None
    if status.casefold() != "active":
        availability = "Unavailable"
    elif family != "unknown":
        folded_name = flavor_name.casefold()
        for key, value in availability_maps[family].items():
            if key in folded_name:
                availability = value
                availability_key = key
                break

    selectable = (
        status.casefold() == "active" and availability.casefold() in _SELECTABLE_AVAILABILITY
    )
    return {
        "flavor_id": flavor_id,
        "name": flavor_name,
        "create_value": flavor_name,
        "gpu_family": family.upper() if family != "unknown" else "Unknown",
        "status": status,
        "availability": availability,
        "availability_source_key": availability_key,
        "selectable": selectable,
        "on_demand_price_inr": cost,
        "billing_unit": unit,
        "gpu_count": gpu_count,
        "ram_gb": ram_gb,
        "gpu_memory_gb": gpu_memory_gb,
        "vcpus": vcpus,
    }


def _normalize_template(entry: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    template_id = entry.get("ID")
    if type(template_id) is not int or template_id < 1:
        raise ValueError(
            f"list_kpod_templates returned an entry at index {index} with an invalid ID"
        )

    template_name = entry.get("template_name")
    if not isinstance(template_name, str) or not template_name.strip():
        raise ValueError(
            f"list_kpod_templates returned an entry at index {index} with an invalid template_name"
        )

    normalized: dict[str, Any] = {
        "pod_template_id": template_id,
        "template_name": template_name.strip(),
    }
    for source, target in _STRING_FIELDS.items():
        value = entry.get(source)
        if not isinstance(value, str):
            raise ValueError(
                f"list_kpod_templates returned an entry at index {index} with an invalid {source}"
            )
        normalized[target] = value

    for source, target in _BOOLEAN_FIELDS.items():
        value = entry.get(source)
        if type(value) is not bool:
            raise ValueError(
                f"list_kpod_templates returned an entry at index {index} with an invalid {source}"
            )
        normalized[target] = value

    environment_variables = entry.get("env_variables")
    if environment_variables is not None:
        normalized["environment_variables"] = environment_variables
    return normalized


def list_kpod_templates(client: KrutrimClient) -> dict[str, Any]:
    """List the live KPod templates available to the authenticated caller."""
    response = client.get(_KPOD_TEMPLATE_PATH, cast_to=httpx.Response)
    payload = required_json_response(
        response,
        expected_type=list,
        operation="list_kpod_templates",
    )

    templates: list[dict[str, Any]] = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, Mapping):
            raise ValueError(
                f"list_kpod_templates returned an invalid entry object at index {index}"
            )
        templates.append(_normalize_template(entry, index=index))

    return {
        "live": True,
        "region_scoped": False,
        "selection_required": True,
        "count": len(templates),
        "templates": templates,
    }


def list_kpod_flavors(client: KrutrimClient) -> dict[str, Any]:
    """List the authenticated live KPod flavor and availability catalogs."""
    flavor_response = client.get(_KPOD_FLAVOR_PATH, cast_to=httpx.Response)
    flavor_payload = required_json_response(
        flavor_response,
        expected_type=list,
        operation="list_kpod_flavors",
    )
    resource_response = client.get(
        _KPOD_GPU_RESOURCE_PATH,
        cast_to=httpx.Response,
    )
    resource_payload = required_json_response(
        resource_response,
        expected_type=dict,
        operation="list_kpod_flavors GPU availability",
    )
    availability_maps = _normalize_availability_maps(resource_payload)

    flavors: list[dict[str, Any]] = []
    for index, entry in enumerate(flavor_payload):
        if not isinstance(entry, Mapping):
            raise ValueError(f"list_kpod_flavors returned an invalid entry object at index {index}")
        flavors.append(
            _normalize_flavor(
                entry,
                index=index,
                availability_maps=availability_maps,
            )
        )

    family_order = {"A100": 0, "H100": 1, "Unknown": 2}
    flavors.sort(
        key=lambda flavor: (
            family_order[flavor["gpu_family"]],
            flavor["on_demand_price_inr"],
            flavor["name"],
        )
    )
    return {
        "catalog_type": "live_backend",
        "live": True,
        "region_scoped": False,
        "selection_required": True,
        "live_availability_verified": True,
        "availability_is_snapshot": True,
        "pricing_live_verified": True,
        "warning": (
            "This authenticated catalog is not region-scoped and does not reserve "
            "capacity. Availability can change before creation."
        ),
        "count": len(flavors),
        "selectable_count": sum(flavor["selectable"] for flavor in flavors),
        "flavors": flavors,
    }
