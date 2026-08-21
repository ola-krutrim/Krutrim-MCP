"""VPC port, floating-IP, and port security-group MCP tools."""

from collections.abc import Mapping
from typing import Annotated, Any, List, Optional

from pydantic import Field

from krutrim_mcp_server.adapters.vpc import delete_floating_ip as delete_floating_ip_api
from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import (
    CONFIRM_FIELD,
    REGION_FIELD,
    Region,
    resolve_region,
    run_tool,
    settings,
)
from krutrim_mcp_server.tools.shared.common import drop_none

VpcKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^krn:vpc:(?:In-Bangalore-1|In-Hyderabad-1):"
            r"[^:]+:[^:]+:vpc:[^:]+$"
        ),
        description="Full VPC KRN for the selected region.",
    ),
]
PortKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^krn:vpc:(?:In-Bangalore-1|In-Hyderabad-1):"
            r"[^:]+:[^:]+:port:[^:]+$"
        ),
        description="Full VPC port KRN copied from search_ports or instance details.",
    ),
]
FloatingIpPortKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^krn:vpc:(?:In-Bangalore-1|In-Hyderabad-1):"
            r"[^:]+:[^:]+:port:[^:]+$"
        ),
        description=(
            "Current reservation-port KRN for the floating IP, copied from "
            "list_floating_ips. This is sent as attach_port to the backend."
        ),
    ),
]
FloatingIpKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^krn:vpc:(?:In-Bangalore-1|In-Hyderabad-1):"
            r"[^:]+:[^:]+:floatingIP:[^:]+$"
        ),
        description=(
            "Full floating-IP KRN copied from list_floating_ips. Deleting it "
            "permanently returns the address to the public pool."
        ),
    ),
]
VmPortKrn = Annotated[
    str,
    Field(
        min_length=1,
        pattern=(
            r"^krn:vpc:(?:In-Bangalore-1|In-Hyderabad-1):"
            r"[^:]+:[^:]+:port:[^:]+$"
        ),
        description=(
            "Destination VM port KRN copied from instance details. This is sent "
            "as detach_port to the backend."
        ),
    ),
]
SecurityGroupKrns = Annotated[
    List[str],
    Field(
        min_length=1,
        description=(
            "Complete replacement list of full security-group KRNs for the port. "
            "Every KRN must belong to the selected VPC and region."
        ),
    ),
]


def _field(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _items(value: Any, field: str) -> list[Any]:
    if isinstance(value, list):
        return value
    items = _field(value, field)
    return list(items) if isinstance(items, (list, tuple)) else []


def _validate_scoped_krn(
    value: str,
    *,
    label: str,
    service: str,
    resource_type: str,
    region: str,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty full Krutrim KRN")
    normalized = value.strip()
    parts = normalized.split(":")
    if (
        len(parts) != 7
        or any(not part for part in parts)
        or parts[0] != "krn"
        or parts[1] != service
        or parts[5] != resource_type
    ):
        raise ValueError(f"{label} must be a full Krutrim {resource_type} KRN")
    if parts[2] != region:
        raise ValueError(
            f"{label} region {parts[2]!r} does not match selected region {region!r}"
        )
    return normalized


def _validate_vpc_krn(vpc_id: str, *, region: str) -> str:
    return _validate_scoped_krn(
        vpc_id,
        label="vpc_id",
        service="vpc",
        resource_type="vpc",
        region=region,
    )


def _validate_vpc_resource_scope(resource_krn: str, *, vpc_krn: str, label: str) -> None:
    resource_parts = resource_krn.split(":")
    vpc_parts = vpc_krn.split(":")
    if resource_parts[3:5] != vpc_parts[3:5]:
        raise ValueError(f"{label} does not belong to the selected VPC account scope")


def _validate_port_krn(port_krn: str, *, vpc_krn: str, region: str, label: str) -> str:
    normalized = _validate_scoped_krn(
        port_krn,
        label=label,
        service="vpc",
        resource_type="port",
        region=region,
    )
    _validate_vpc_resource_scope(normalized, vpc_krn=vpc_krn, label=label)
    return normalized


def _validate_floating_ip_krn(
    floating_ip_krn: str,
    *,
    vpc_krn: str,
    region: str,
) -> str:
    normalized = _validate_scoped_krn(
        floating_ip_krn,
        label="floating_ip_krn",
        service="vpc",
        resource_type="floatingIP",
        region=region,
    )
    _validate_vpc_resource_scope(
        normalized,
        vpc_krn=vpc_krn,
        label="floating_ip_krn",
    )
    return normalized


def _validate_security_group_krns(
    security_group_ids: List[str],
    *,
    vpc_krn: str,
    region: str,
) -> list[str]:
    if not isinstance(security_group_ids, list) or not security_group_ids:
        raise ValueError("security_group_ids must contain at least one full security-group KRN")

    resolved: list[str] = []
    for value in security_group_ids:
        normalized = _validate_scoped_krn(
            value,
            label="security_group_ids entry",
            service="krutrim-sg",
            resource_type="sg",
            region=region,
        )
        _validate_vpc_resource_scope(
            normalized,
            vpc_krn=vpc_krn,
            label="security_group_ids entry",
        )
        resolved.append(normalized)
    if len(set(resolved)) != len(resolved):
        raise ValueError("security_group_ids must not contain duplicates")
    return resolved


def _preflight_exact_port(client: Any, *, port_krn: str, vpc_krn: str, region: str) -> Any:
    response = client.highlvlvpc.search_ports(
        x_region=region,
        vpc_id=vpc_krn,
        port_id=port_krn,
        page=1,
        size=100,
    )
    matches = [
        item
        for item in _items(response, "ports")
        if any(
            _field(item, identifier_field) == port_krn
            for identifier_field in ("krn_id", "port_id", "id")
        )
    ]
    if len(matches) != 1:
        raise ValueError(
            "port identity preflight did not return exactly the requested port; "
            "operation blocked"
        )
    return matches[0]


def _floating_ip_for_port(client: Any, *, port_krn: str, vpc_krn: str, region: str) -> Any:
    response = client.highlvlvpc.list_floating_ips(vpc_id=vpc_krn, x_region=region)
    matches = [item for item in _items(response, "items") if _field(item, "port_krn") == port_krn]
    if len(matches) != 1:
        raise ValueError(
            "floating-IP preflight did not return exactly one address for the requested port; "
            "operation blocked"
        )
    return matches[0]


def _floating_ip_by_krn(
    client: Any,
    *,
    floating_ip_krn: str,
    vpc_krn: str,
    region: str,
) -> Any:
    response = client.highlvlvpc.list_floating_ips(vpc_id=vpc_krn, x_region=region)
    matches = [
        item
        for item in _items(response, "items")
        if _field(item, "floating_ip_krn") == floating_ip_krn
    ]
    if len(matches) != 1:
        raise ValueError(
            "floating-IP preflight did not return exactly the requested address; "
            "operation blocked"
        )
    return matches[0]


def _preflight_security_groups(
    client: Any,
    *,
    security_group_ids: list[str],
    vpc_krn: str,
    region: str,
) -> None:
    response = client.securityGroup.list_by_vpc(
        vpc_krn_identifier=vpc_krn,
        x_region=region,
        limit=1000,
        offset=0,
        extra_query={"limit": 1000, "offset": 0},
    )
    groups = _items(response, "items") or _items(response, "result")
    total_count = _field(response, "total_count")
    if not isinstance(total_count, int):
        pagination = _field(response, "pagination")
        total_count = _field(pagination, "total_count")
        if not isinstance(total_count, int):
            total_count = _field(pagination, "totalCount")
    if isinstance(total_count, int) and total_count > len(groups):
        raise ValueError("security-group inventory was truncated; operation blocked")
    available = {
        group_id
        for group in groups
        if isinstance((group_id := _field(group, "id")), str) and group_id
    }
    missing = sorted(set(security_group_ids) - available)
    if missing:
        raise ValueError(
            "security-group preflight did not find every requested KRN in the selected VPC: "
            + ", ".join(missing)
        )


def register(mcp: Any) -> None:
    @mcp.tool()
    def search_vpcs(
        region: Region = REGION_FIELD,
        name: Optional[str] = None,
        status: Optional[str] = None,
        page: Optional[int] = None,
        size: Optional[int] = None,
    ) -> str:
        """Search VPCs."""

        def _run() -> Any:
            return get_session().get_client().highlvlvpc.search_vpcs(
                **drop_none(
                    {
                        "extra_headers": {"x-region": resolve_region(region)},
                        "name": name,
                        "status": status,
                        "page": page,
                        "size": size,
                    }
                )
            )

        return run_tool(_run)

    @mcp.tool()
    def search_ports(
        region: Region = REGION_FIELD,
        vpc_id: Optional[str] = None,
        network_id: Optional[str] = None,
        port_id: Optional[str] = None,
        name: Optional[str] = None,
        status: Optional[str] = None,
        page: Optional[int] = None,
        size: Optional[int] = None,
    ) -> str:
        """Search ports in a region."""

        def _run() -> Any:
            return get_session().get_client().highlvlvpc.search_ports(
                **drop_none(
                    {
                        "x_region": resolve_region(region),
                        "vpc_id": vpc_id,
                        "network_id": network_id,
                        "port_id": port_id,
                        "name": name,
                        "status": status,
                        "page": page,
                        "size": size,
                    }
                )
            )

        return run_tool(_run)

    @mcp.tool()
    def list_floating_ips(
        vpc_id: VpcKrn,
        region: Region = REGION_FIELD,
    ) -> str:
        """List floating IPs reserved or attached in one explicit VPC."""

        def _run() -> Any:
            x_region = resolve_region(region)
            resolved_vpc = _validate_vpc_krn(vpc_id, region=x_region)
            return get_session().get_client().highlvlvpc.list_floating_ips(
                vpc_id=resolved_vpc,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_port(
        name: str,
        network_id: str,
        subnet_id: str,
        vpc_id: str,
        floating_ip: bool = False,
        allow_public_ip: bool = False,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a VPC port and optionally reserve a public floating IP."""

        def _run() -> Any:
            ensure_writable(settings(), "create_port")
            ensure_confirmed(confirm, "create_port", name)
            if floating_ip and not allow_public_ip:
                raise ValueError(
                    "floating_ip=true requires allow_public_ip=true after explicit user approval"
                )
            return get_session().get_client().highlvlvpc.create_port(
                floating_ip=floating_ip,
                name=name,
                network_id=network_id,
                subnet_id=subnet_id,
                vpc_id=vpc_id,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def attach_floating_ip(
        vpc_id: VpcKrn,
        attach_port: FloatingIpPortKrn,
        detach_port: VmPortKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Attach a reserved floating IP to a VM using the backend port contract
        """

        def _run() -> Any:
            ensure_writable(settings(), "attach_floating_ip")
            ensure_confirmed(
                confirm,
                "attach_floating_ip",
                f"attach floating IP on {attach_port} to VM port {detach_port}",
            )
            x_region = resolve_region(region)
            resolved_vpc = _validate_vpc_krn(vpc_id, region=x_region)
            resolved_attach_port = _validate_port_krn(
                attach_port,
                vpc_krn=resolved_vpc,
                region=x_region,
                label="attach_port",
            )
            resolved_detach_port = _validate_port_krn(
                detach_port,
                vpc_krn=resolved_vpc,
                region=x_region,
                label="detach_port",
            )
            if resolved_attach_port == resolved_detach_port:
                raise ValueError("attach_port and detach_port must be different ports")
            client = get_session().get_client()
            _preflight_exact_port(
                client,
                port_krn=resolved_detach_port,
                vpc_krn=resolved_vpc,
                region=x_region,
            )
            _floating_ip_for_port(
                client,
                port_krn=resolved_attach_port,
                vpc_krn=resolved_vpc,
                region=x_region,
            )
            return client.highlvlvpc.attach_floating_ip(
                attach_port=resolved_attach_port,
                detach_port=resolved_detach_port,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def detach_floating_ip(
        vpc_id: VpcKrn,
        port_krn: PortKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Detach a floating IP from a port while retaining its reservation."""

        def _run() -> Any:
            ensure_writable(settings(), "detach_floating_ip")
            ensure_confirmed(confirm, "detach_floating_ip", port_krn)
            x_region = resolve_region(region)
            resolved_vpc = _validate_vpc_krn(vpc_id, region=x_region)
            resolved_port = _validate_port_krn(
                port_krn,
                vpc_krn=resolved_vpc,
                region=x_region,
                label="port_krn",
            )
            client = get_session().get_client()
            _floating_ip_for_port(
                client,
                port_krn=resolved_port,
                vpc_krn=resolved_vpc,
                region=x_region,
            )
            return client.highlvlvpc.detach_floating_ip(
                port_krn=resolved_port,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_floating_ip(
        vpc_id: VpcKrn,
        floating_ip_krn: FloatingIpKrn,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Permanently unreserve a detached floating IP and return it to the pool."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_floating_ip")
            ensure_confirmed(confirm, "delete_floating_ip", floating_ip_krn)
            x_region = resolve_region(region)
            resolved_vpc = _validate_vpc_krn(vpc_id, region=x_region)
            resolved_floating_ip = _validate_floating_ip_krn(
                floating_ip_krn,
                vpc_krn=resolved_vpc,
                region=x_region,
            )
            client = get_session().get_client()
            inventory_item = _floating_ip_by_krn(
                client,
                floating_ip_krn=resolved_floating_ip,
                vpc_krn=resolved_vpc,
                region=x_region,
            )
            vm_name = _field(inventory_item, "vm_name")
            if (
                isinstance(vm_name, str)
                and vm_name.strip()
                and vm_name.strip().lower() != "unknown"
            ):
                raise ValueError(
                    f"floating IP is still attached to VM {vm_name!r}; "
                    "detach it before deleting the reservation"
                )
            return delete_floating_ip_api(
                client,
                floating_ip_krn=resolved_floating_ip,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def update_port_security_groups(
        vpc_id: VpcKrn,
        port_krn: PortKrn,
        security_group_ids: SecurityGroupKrns,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Replace the complete security-group list on one exact VPC port.

        Any currently attached group omitted from security_group_ids is removed.
        """

        def _run() -> Any:
            ensure_writable(settings(), "update_port_security_groups")
            ensure_confirmed(
                confirm,
                "update_port_security_groups",
                f"{port_krn} -> {security_group_ids}",
            )
            x_region = resolve_region(region)
            resolved_vpc = _validate_vpc_krn(vpc_id, region=x_region)
            resolved_port = _validate_port_krn(
                port_krn,
                vpc_krn=resolved_vpc,
                region=x_region,
                label="port_krn",
            )
            resolved_groups = _validate_security_group_krns(
                security_group_ids,
                vpc_krn=resolved_vpc,
                region=x_region,
            )
            client = get_session().get_client()
            _preflight_exact_port(
                client,
                port_krn=resolved_port,
                vpc_krn=resolved_vpc,
                region=x_region,
            )
            _preflight_security_groups(
                client,
                security_group_ids=resolved_groups,
                vpc_krn=resolved_vpc,
                region=x_region,
            )
            return client.highlvlvpc.update_port_security_groups(
                resolved_port,
                security_groups=resolved_groups,
                x_region=x_region,
            )

        return run_tool(_run)
