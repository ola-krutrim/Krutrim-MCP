"""DNS MCP tools."""

from typing import Any, Literal, Optional

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.compat import sdk_raw_result, sdk_response_json
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import CONFIRM_FIELD, run_tool, settings
from krutrim_mcp_server.tools.shared.common import drop_none


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_dns_zones() -> str:
        """List DNS zones."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(client.v1.with_raw_response.list_zones)

        return run_tool(_run)

    @mcp.tool()
    def get_dns_zone(zone_id: str) -> str:
        """Fetch a DNS zone by id."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.zone.with_raw_response.fetchZoneById,
                zone_id,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_dns_zone(
        zone_name: str,
        zone_type: Literal["public", "private"],
        vpc_id: str,
        subnet_id: str,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a DNS zone."""

        def _run() -> Any:
            ensure_writable(settings(), "create_dns_zone")
            ensure_confirmed(confirm, "create_dns_zone", zone_name)
            client = get_session().get_client()
            return sdk_raw_result(
                client.zone.with_raw_response.create,
                zonename=zone_name,
                type=zone_type,
                vpcid=vpc_id,
                subnetid=subnet_id,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_dns_zone(zone_id: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete a DNS zone."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_dns_zone")
            ensure_confirmed(confirm, "delete_dns_zone", zone_id)
            client = get_session().get_client()
            return sdk_raw_result(client.zone.with_raw_response.delete, zone_id)

        return run_tool(_run)

    @mcp.tool()
    def list_dns_records(zone_id: str) -> str:
        """List DNS records for a zone."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.record.with_raw_response.fetchrecord,
                zone_id,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_dns_record(
        zone_krn: str,
        record_name: str,
        record_type: str,
        value: str,
        ttl: int,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a DNS record."""

        def _run() -> Any:
            ensure_writable(settings(), "create_dns_record")
            ensure_confirmed(confirm, "create_dns_record", record_name)
            client = get_session().get_client()
            return sdk_raw_result(
                client.record.with_raw_response.create,
                krnid=zone_krn,
                rname=record_name,
                TYPE=record_type,
                value=value,
                ttl=ttl,
            )

        return run_tool(_run)

    @mcp.tool()
    def update_dns_record(
        record_id: str,
        record_name: str,
        value: str,
        record_type: Optional[str] = None,
        routing: Optional[str] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Update a DNS record."""

        def _run() -> Any:
            ensure_writable(settings(), "update_dns_record")
            ensure_confirmed(confirm, "update_dns_record", record_id)
            client = get_session().get_client()
            return sdk_raw_result(
                client.record.with_raw_response.update,
                record_id,
                record_name,
                **drop_none(
                    {
                        "TYPE": record_type,
                        "value": value,
                        "routing": routing,
                        # Remove SDK Omit sentinels.
                        "extra_body": {},
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_dns_record(record_id: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete a DNS record."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_dns_record")
            ensure_confirmed(confirm, "delete_dns_record", record_id)
            client = get_session().get_client()
            return sdk_raw_result(client.record.with_raw_response.delete, record_id)

        return run_tool(_run)

    @mcp.tool()
    def add_dns_zone_vpc(
        zone_id: str,
        vpc_info: list[str],
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Attach VPC info to a private DNS zone."""

        def _run() -> Any:
            ensure_writable(settings(), "add_dns_zone_vpc")
            ensure_confirmed(confirm, "add_dns_zone_vpc", zone_id)
            client = get_session().get_client()
            return sdk_raw_result(
                client.vpc.with_raw_response.add,
                zone_id,
                vpcinfo=vpc_info,
            )

        return run_tool(_run)

    @mcp.tool()
    def remove_dns_zone_vpc(
        zone_id: str,
        vpc_info: list[str],
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Remove VPC info from a private DNS zone."""

        def _run() -> Any:
            ensure_writable(settings(), "remove_dns_zone_vpc")
            ensure_confirmed(confirm, "remove_dns_zone_vpc", zone_id)
            client = get_session().get_client()
            return sdk_raw_result(
                client.vpc.with_raw_response.remove,
                zone_id,
                vpcinfo=vpc_info,
            )

        return run_tool(_run)
