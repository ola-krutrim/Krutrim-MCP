"""VPC and networking MCP tools."""

import ipaddress
from typing import Annotated, Any

from krutrim_client import KrutrimClient
from pydantic import Field

from krutrim_mcp_server.adapters.vpc import create_vpc_without_security_fields
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
from krutrim_mcp_server.tools.networking.subnets import subnet_inventory

_INACTIVE_VPC_STATUSES = frozenset(
    {
        "DELETED",
        "DELETE",
        "FAILED",
        "ERROR",
        "TERMINATED",
        "INACTIVE",
        "DELETING",
        "NOT FOUND",
    }
)
SubnetCIDR = Annotated[
    str,
    Field(description="Explicit IPv4 subnet range with usable host and gateway addresses"),
]
VpcName = Annotated[
    str,
    Field(min_length=1, description="Name for the VPC and its associated network"),
]


def _vpc_status(vpc: Any) -> str:
    for field in ("operating_status", "status", "state"):
        value = vpc.get(field) if isinstance(vpc, dict) else getattr(vpc, field, None)
        if value is not None and str(value).strip():
            return str(value).strip().upper()
    return ""


def _is_active_vpc(vpc: Any) -> bool:
    status = _vpc_status(vpc)
    if not status:
        return True
    return status not in _INACTIVE_VPC_STATUSES


def _vpc_region(vpc: Any) -> str:
    vpc_id = ""
    if isinstance(vpc, dict):
        vpc_id = str(vpc.get("vpcId") or vpc.get("vpc_id") or vpc.get("id") or "")
    else:
        vpc_id = str(
            getattr(vpc, "vpcId", None)
            or getattr(vpc, "vpc_id", None)
            or getattr(vpc, "id", None)
            or ""
        )
    parts = vpc_id.split(":")
    if len(parts) > 2 and parts[0] == "krn":
        return parts[2]
    return ""


def _matches_region(vpc: Any, region: str) -> bool:
    row_region = _vpc_region(vpc)
    return not row_region or row_region == region


def _filter_vpcs(response: Any, *, region: str, include_inactive: bool) -> Any:
    def _keep(vpc: Any) -> bool:
        return _matches_region(vpc, region) and (include_inactive or _is_active_vpc(vpc))

    if isinstance(response, list):
        return [vpc for vpc in response if _keep(vpc)]

    if isinstance(response, dict):
        filtered = dict(response)
        for key in ("vpcs", "items", "data"):
            if isinstance(filtered.get(key), list):
                filtered[key] = [vpc for vpc in filtered[key] if _keep(vpc)]
                return filtered

    return response


def _delete_vpc(client: KrutrimClient, vpc_id: str, x_region: str) -> None:
    """Delete a VPC through the client surface."""
    client.highlvlvpc.delete_vpc(vpc_id=vpc_id, x_region=x_region)


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_vpcs(
        region: Region = REGION_FIELD,
        include_inactive: bool = True,
    ) -> str:
        """List VPCs, including failed/deleting resources by default."""

        def _run() -> Any:
            client = get_session().get_client()
            x_region = resolve_region(region)
            response = client.highlvlvpc.list_vpcs(x_region=x_region)
            return _filter_vpcs(
                response,
                region=x_region,
                include_inactive=include_inactive,
            )

        return run_tool(_run)

    @mcp.tool()
    def describe_vpc(vpc_id: str, region: Region = REGION_FIELD) -> str:
        """Describe a VPC by ID in a region."""

        def _run() -> Any:
            client = get_session().get_client()
            return client.highlvlvpc.retrieve_vpc(
                vpc_id=vpc_id, x_region=resolve_region(region)
            )

        return run_tool(_run)

    @mcp.tool()
    def list_subnets(vpc_id: str, region: Region = REGION_FIELD) -> str:
        """List selectable subnet KRNs for a VPC.

        Use ``subnets[].subnet_id`` for VM creation. ``parent_network_id`` is
        included only as context and is never a valid ``subnet_id``.
        """

        def _run() -> Any:
            client = get_session().get_client()
            response = client.highlvlvpc.search_networks(
                vpc_id=vpc_id,
                x_region=resolve_region(region),
            )
            return subnet_inventory(response, vpc_id=vpc_id)

        return run_tool(_run)

    @mcp.tool()
    def get_vpc_task_status(task_id: str, region: Region = REGION_FIELD) -> str:
        """Poll async VPC create/update task status by task_id."""

        def _run() -> Any:
            client = get_session().get_client()
            return client.highlvlvpc.get_vpc_task_status(
                task_id=task_id, x_region=resolve_region(region)
            )

        return run_tool(_run)

    @mcp.tool()
    def create_vpc(
        name: VpcName,
        subnet_cidr: SubnetCIDR,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """
        Create a VPC, network, and subnet without a security group
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_vpc")
            vpc_name = name.strip()
            if not vpc_name:
                raise ValueError("name cannot be blank")
            ensure_confirmed(confirm, "create_vpc", vpc_name)
            x_region = resolve_region(region)
            subnet_network = ipaddress.ip_network(subnet_cidr, strict=False)
            if subnet_network.version != 4:
                raise ValueError("create_vpc currently supports IPv4 CIDRs only")
            if subnet_network.prefixlen > 30:
                raise ValueError("subnet_cidr must contain usable host and gateway addresses")
            network = {"admin_state_up": True, "name": f"{vpc_name}-network"}
            subnet = {
                "name": f"{vpc_name}-subnet",
                "cidr": str(subnet_network),
                "description": f"Default-subnet-for-{vpc_name}",
                "gateway_ip": str(subnet_network.network_address + 1),
                "ip_version": "4",
                # Subnet accessibility fields, not security rules.
                "ingress": True,
                "egress": True,
            }
            vpc = {
                "name": vpc_name,
                "description": f"VPC-{vpc_name}",
                "enabled": True,
            }
            client = get_session().get_client()
            return create_vpc_without_security_fields(
                client,
                network=network,
                subnet=subnet,
                vpc=vpc,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_subnet(
        vpc_id: str,
        name: str,
        cidr: str,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a subnet in an existing VPC."""

        def _run() -> Any:
            ensure_writable(settings(), "create_subnet")
            ensure_confirmed(confirm, "create_subnet", name)
            client = get_session().get_client()
            subnet_network = ipaddress.ip_network(cidr, strict=False)
            if subnet_network.version != 4:
                raise ValueError("create_subnet currently supports IPv4 CIDRs only")
            if subnet_network.prefixlen > 30:
                raise ValueError("cidr must contain usable host and gateway addresses")
            subnet_data = {
                "name": name,
                "cidr": str(subnet_network),
                "description": f"Subnet-for-{name}",
                "gateway_ip": str(subnet_network.network_address + 1),
                "ip_version": 4,
                "ingress": True,
                "egress": True,
            }
            return client.highlvlvpc.create_subnet(
                subnet_data=subnet_data,
                vpc_id=vpc_id,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_vpc(
        vpc_id: str,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """Delete a VPC."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_vpc")
            ensure_confirmed(confirm, "delete_vpc", vpc_id)
            x_region = resolve_region(region)
            client = get_session().get_client()
            _delete_vpc(client, vpc_id, x_region)
            return {"deleted": True, "vpc_id": vpc_id}

        return run_tool(_run)
