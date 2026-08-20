"""Subnet discovery normalization and fail-closed VM subnet validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any

from pydantic import Field

SubnetId = Annotated[
    str,
    Field(
        min_length=1,
        description=(
            "A subnet KRN from list_subnets.subnets[].subnet_id. Never pass "
            "parent_network_id; full subnet KRNs are verified against the selected VPC "
            "before VM-related creates."
        ),
    ),
]


def _field_value(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _optional_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _network_rows(response: Any, *, vpc_id: str) -> list[dict[str, Any]]:
    if not isinstance(response, (list, tuple)):
        raise ValueError(
            "subnet preflight returned an invalid network inventory; no VM create request was sent"
        )

    rows: list[dict[str, Any]] = []
    for index, network in enumerate(response):
        network_id = _optional_text(_field_value(network, "network_id"))
        subnets = _field_value(network, "subnets")
        row_vpc_id = _optional_text(_field_value(network, "vpc_id"))
        if row_vpc_id is not None and row_vpc_id != vpc_id:
            raise ValueError(
                "subnet preflight returned a network outside the requested VPC; "
                "no VM create request was sent"
            )
        if subnets is None:
            subnet_ids: list[str] = []
        elif isinstance(subnets, (list, tuple)):
            subnet_ids = [
                subnet_id
                for subnet in subnets
                if (subnet_id := _optional_text(subnet)) is not None
            ]
        else:
            raise ValueError(
                f"subnet preflight returned malformed subnets for network entry {index}; "
                "no VM create request was sent"
            )
        rows.append(
            {
                "network_id": network_id,
                "network_name": _optional_text(_field_value(network, "name")),
                "network_status": _optional_text(_field_value(network, "status")),
                "subnet_ids": subnet_ids,
            }
        )
    return rows


def subnet_inventory(response: Any, *, vpc_id: str) -> dict[str, Any]:
    """Return subnet-first discovery data without conflating network and subnet KRNs."""
    rows = _network_rows(response, vpc_id=vpc_id)
    subnets: list[dict[str, str]] = []
    for row in rows:
        for subnet_id in row["subnet_ids"]:
            entry: dict[str, str] = {"subnet_id": subnet_id}
            if row["network_id"] is not None:
                entry["parent_network_id"] = row["network_id"]
            if row["network_name"] is not None:
                entry["network_name"] = row["network_name"]
            if row["network_status"] is not None:
                entry["network_status"] = row["network_status"]
            subnets.append(entry)
    return {
        "vpc_id": vpc_id,
        "subnets": subnets,
        "guidance": (
            "Pass a value from subnets[].subnet_id to create_instance or "
            "create_instance_template. parent_network_id is not a subnet and must not "
            "be supplied as subnet_id."
        ),
    }


def _krn_resource_kind(value: str) -> str | None:
    """Classify both known KRN layouts without inferring account identity."""
    parts = [part.strip() for part in value.split(":")]
    if not parts or parts[0].casefold() != "krn":
        return None

    # Current Cloud responses can use either ``...:subnet:<id>`` or a compact
    # terminal resource segment such as ``...:subnet/<id>``.
    terminal = parts[-1]
    if "/" in terminal:
        kind = terminal.partition("/")[0].strip()
        return kind.casefold() or None
    if len(parts) >= 2:
        kind = parts[-2].strip()
        return kind.casefold() or None
    return None


def validate_subnet_reference(subnet_id: str) -> tuple[str, bool]:
    """Validate local subnet syntax and return whether live membership is required.

    Legacy non-KRN subnet IDs remain supported for SDK compatibility. Every KRN is
    fail-closed: it must unambiguously identify a subnet, never a parent network.
    """
    normalized = _optional_text(subnet_id)
    if normalized is None:
        raise ValueError("subnet_id must be a non-empty subnet KRN or legacy subnet ID")
    if not normalized.casefold().startswith("krn:"):
        return normalized, False

    kind = _krn_resource_kind(normalized)
    if kind == "network":
        raise ValueError(
            "subnet_id is a network KRN, not a subnet KRN. Use a value from "
            "list_subnets.subnets[].subnet_id; no VM create request was sent"
        )
    if kind != "subnet":
        raise ValueError(
            "subnet_id must be a subnet KRN. Use a value from "
            "list_subnets.subnets[].subnet_id; no VM create request was sent"
        )
    return normalized, True


def verify_subnet_membership(
    client: Any,
    *,
    vpc_id: str,
    subnet_id: str,
    region: str,
) -> str:
    """Require the selected subnet KRN to be an exact member of the selected VPC."""
    response = client.highlvlvpc.search_networks(
        vpc_id=vpc_id,
        x_region=region,
    )
    rows = _network_rows(response, vpc_id=vpc_id)
    network_matches = [row for row in rows if row["network_id"] == subnet_id]
    if network_matches:
        raise ValueError(
            "subnet_id is a network KRN, not a subnet KRN. Use a value from "
            "list_subnets.subnets[].subnet_id; no VM create request was sent"
        )

    matches = [
        row
        for row in rows
        for candidate_subnet_id in row["subnet_ids"]
        if candidate_subnet_id == subnet_id
    ]
    if not matches:
        raise ValueError(
            "subnet_id is not a subnet of the selected VPC. Use a value from "
            "list_subnets.subnets[].subnet_id; no VM create request was sent"
        )
    if len(matches) > 1:
        raise ValueError(
            "subnet_id appears in multiple networks in the selected VPC; refusing "
            "an ambiguous VM create request"
        )
    return subnet_id
