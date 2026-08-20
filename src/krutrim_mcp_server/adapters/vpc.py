"""Direct VPC API adapter for the current wire contract."""

from collections.abc import Mapping
from typing import Any

import httpx
from krutrim_client import KrutrimClient

from krutrim_mcp_server.adapters._http import response_payload
from krutrim_mcp_server.config import KNOWN_REGIONS

_CREATE_VPC_PATH = "/v1/highlvlvpc/create_vpc_async"
_DELETE_FLOATING_IP_PATH = "/v1/highlvlvpc/delete_floating_ip"
_CREATE_VPC_FIELD_TYPES = {
    "network": {"admin_state_up": bool, "name": str},
    "subnet": {
        "cidr": str,
        "description": str,
        "egress": bool,
        "gateway_ip": str,
        "ingress": bool,
        "ip_version": str,
        "name": str,
    },
    "vpc": {"description": str, "enabled": bool, "name": str},
}
_CREATE_VPC_OPTIONAL_FIELDS = {
    "network": frozenset(),
    "subnet": frozenset({"description"}),
    "vpc": frozenset({"description"}),
}
_CREATE_VPC_NONEMPTY_FIELDS = {
    ("network", "name"),
    ("subnet", "cidr"),
    ("subnet", "gateway_ip"),
    ("subnet", "ip_version"),
    ("subnet", "name"),
    ("vpc", "name"),
}


def create_vpc_without_security_fields(
    client: KrutrimClient,
    *,
    network: Mapping[str, Any],
    subnet: Mapping[str, Any],
    vpc: Mapping[str, Any],
    x_region: str,
) -> dict[str, Any]:
    """Create a VPC without the SDK's obsolete required security fields."""
    body = {"network": dict(network), "subnet": dict(subnet), "vpc": dict(vpc)}
    for section, field_types in _CREATE_VPC_FIELD_TYPES.items():
        values = body[section]
        unexpected = set(values) - set(field_types)
        if unexpected:
            names = ", ".join(sorted(unexpected))
            raise ValueError(f"Unexpected {section} fields in VPC create request: {names}")
        required = set(field_types) - _CREATE_VPC_OPTIONAL_FIELDS[section]
        missing = required - set(values)
        if missing:
            names = ", ".join(sorted(missing))
            raise ValueError(f"Missing {section} fields in VPC create request: {names}")
        for field, expected_type in field_types.items():
            if field not in values:
                continue
            value = values[field]
            valid_type = (
                type(value) is bool
                if expected_type is bool
                else isinstance(value, expected_type)
            )
            if not valid_type:
                raise TypeError(
                    f"VPC create field {section}.{field} must be "
                    f"{expected_type.__name__}"
                )
            if (section, field) in _CREATE_VPC_NONEMPTY_FIELDS and not value.strip():
                raise ValueError(f"VPC create field {section}.{field} cannot be blank")
    if x_region not in KNOWN_REGIONS:
        raise ValueError(f"Unsupported VPC create region: {x_region}")
    if body["subnet"]["ip_version"] != "4":
        raise ValueError("VPC create currently supports ip_version=4 only")

    response = client.post(
        _CREATE_VPC_PATH,
        cast_to=httpx.Response,
        body=body,
        options={"headers": {"x-region": x_region}},
    )
    return response_payload(response)


def delete_floating_ip(
    client: KrutrimClient,
    *,
    floating_ip_krn: str,
    x_region: str,
) -> dict[str, Any]:
    """Permanently release a detached floating IP through the direct API."""
    if not isinstance(floating_ip_krn, str) or not floating_ip_krn.strip():
        raise ValueError("floating_ip_krn must be a non-empty string")
    if x_region not in KNOWN_REGIONS:
        raise ValueError(f"Unsupported floating-IP delete region: {x_region}")

    response = client.delete(
        _DELETE_FLOATING_IP_PATH,
        cast_to=httpx.Response,
        options={
            "headers": {"x-region": x_region},
            "params": {"floating_ip_krn": floating_ip_krn.strip()},
            "max_retries": 0,
        },
    )
    return response_payload(response)
