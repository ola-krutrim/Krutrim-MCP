"""Load balancer and target group MCP tools."""

from typing import Any, Optional

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
from krutrim_mcp_server.tools.shared.common import drop_none


def _require_text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _identity_from_krn(krn: str, *, label: str) -> tuple[str, str]:
    """Return (customer_id, account_id) from a full 7-part KRN.

    KRN layout: krn:<service>:<region>:<account>:<customer>:<type>:<id>. Load
    balancer create/update and target-group describe/update need both values as
    request headers, so they are derived from a KRN the caller already owns.
    """
    value = _require_text(krn, label)
    if ":***:" in value:
        raise ValueError(
            f"{label} contains a masked account segment (':***:'). Krutrim tool "
            "output redacts the account id in returned KRNs, but the API rejects "
            "masked KRNs as input. Replace '***' with your account (customer) "
            "UUID before calling this tool."
        )
    parts = value.split(":")
    if len(parts) < 7 or parts[0] != "krn" or not parts[3] or not parts[4]:
        raise ValueError(
            f"{label} must be a full KRN of the form "
            "krn:<service>:<region>:<account>:<customer>:<type>:<id>"
        )
    return parts[4], parts[3]


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_load_balancers(vpc_id: str, region: Region = REGION_FIELD) -> str:
        """List load balancers in a VPC.

        vpc_id is the full VPC KRN. Returns the load balancers with their
        provisioning status; use describe_load_balancer for one in detail.
        """

        def _run() -> Any:
            vpc = _require_text(vpc_id, "vpc_id")
            client = get_session().get_client()
            return sdk_response_json(
                client.lb.with_raw_response.list_load_balancers_by_vpc,
                vpc,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def describe_load_balancer(lb_krn: str, region: Region = REGION_FIELD) -> str:
        """Describe one load balancer by KRN (listeners, pools, members, status)."""

        def _run() -> Any:
            lb = _require_text(lb_krn, "lb_krn")
            client = get_session().get_client()
            return sdk_response_json(
                client.lb.with_raw_response.get_load_balancer_details,
                lb,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def get_load_balancer_payload(lb_krn: str, region: Region = REGION_FIELD) -> str:
        """Fetch the editable configuration payload of a load balancer.

        Use this to read the current `loadbalancer_data` and `listeners` shape
        before calling update_load_balancer, so an update changes only what you
        intend to.
        """

        def _run() -> Any:
            lb = _require_text(lb_krn, "lb_krn")
            client = get_session().get_client()
            return sdk_response_json(
                client.lb.with_raw_response.fetch_payload_multiple,
                lb,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def get_load_balancer_task_status(task_id: str, region: Region = REGION_FIELD) -> str:
        """Get the status of an asynchronous load balancer task.

        create/update/delete load balancer calls are asynchronous; poll the task
        id they return here to learn whether provisioning finished.
        """

        def _run() -> Any:
            task = _require_text(task_id, "task_id")
            client = get_session().get_client()
            return sdk_response_json(
                client.lb.with_raw_response.get_task_status,
                task,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def list_target_groups(vpc_id: str, region: Region = REGION_FIELD) -> str:
        """List target groups in a VPC.

        Use list_target_group_names for names only, or get_detailed_target_groups
        for the members and health monitor of each group.
        """

        def _run() -> Any:
            vpc = _require_text(vpc_id, "vpc_id")
            client = get_session().get_client()
            return sdk_response_json(
                client.lb.with_raw_response.get_full_tg_list,
                vpc_id=vpc,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def list_target_group_names(vpc_id: str, region: Region = REGION_FIELD) -> str:
        """List only the target group names in a VPC."""

        def _run() -> Any:
            vpc = _require_text(vpc_id, "vpc_id")
            client = get_session().get_client()
            return sdk_response_json(
                client.lb.with_raw_response.get_tg_names_only,
                vpc_id=vpc,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def get_detailed_target_groups(
        vpc_id: str,
        region: Region = REGION_FIELD,
        target_group_name: Optional[str] = None,
    ) -> str:
        """Describe target groups in detail (members, weights, health monitor).

        vpc_id must be the full, unmasked VPC KRN; the account and customer
        identity are derived from it. Omit target_group_name to describe every
        target group in the VPC.
        """

        def _run() -> Any:
            vpc = _require_text(vpc_id, "vpc_id")
            customer_id, account_id = _identity_from_krn(vpc, label="vpc_id")
            x_region = resolve_region(region)
            client = get_session().get_client()
            return sdk_response_json(
                client.lb.with_raw_response.get_detailed_target_groups,
                **drop_none(
                    {
                        "k_customer_id": customer_id,
                        "x_account_id": account_id,
                        "x_region": x_region,
                        "vpc_id": vpc,
                        "target_group_name": target_group_name,
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def create_load_balancer(
        vpc_id: str,
        loadbalancer_data: dict[str, Any],
        region: Region = REGION_FIELD,
        listeners: Optional[list[dict[str, Any]]] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a load balancer (billable, asynchronous).

        loadbalancer_data and listeners are passed to the Krutrim load balancer
        orchestration API unchanged. vpc_id must be the full, unmasked VPC KRN of
        the VPC the load balancer lives in; it is used only to derive the account
        and customer identity headers, so repeat the VPC inside loadbalancer_data
        if the API payload needs it. Returns a task id; poll it with
        get_load_balancer_task_status.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_load_balancer")
            data = loadbalancer_data
            if not isinstance(data, dict):
                raise ValueError("loadbalancer_data must be an object")
            name = str(data.get("name") or data.get("loadbalancer_name") or vpc_id)
            ensure_confirmed(confirm, "create_load_balancer", name)
            vpc = _require_text(vpc_id, "vpc_id")
            customer_id, account_id = _identity_from_krn(vpc, label="vpc_id")
            x_region = resolve_region(region)
            client = get_session().get_client()
            return sdk_raw_result(
                client.lb.with_raw_response.create_load_balancer_orchestration,
                **drop_none(
                    {
                        "k_customer_id": customer_id,
                        "x_account_id": account_id,
                        "x_region": x_region,
                        "loadbalancer_data": data,
                        "listeners": listeners,
                        # Remove SDK Omit sentinels for unset optional fields.
                        "extra_body": {},
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def update_load_balancer(
        lb_krn: str,
        region: Region = REGION_FIELD,
        loadbalancer_data: Optional[dict[str, Any]] = None,
        listeners: Optional[list[dict[str, Any]]] = None,
        security_groups: Optional[list[str]] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Update a load balancer's configuration (asynchronous).

        lb_krn must be the full, unmasked KRN; identity is derived from it. Pass
        only the parts you want to change (loadbalancer_data, listeners,
        security_groups) - read the current shape with get_load_balancer_payload
        first. At least one of them is required.
        """

        def _run() -> Any:
            ensure_writable(settings(), "update_load_balancer")
            ensure_confirmed(confirm, "update_load_balancer", lb_krn)
            lb = _require_text(lb_krn, "lb_krn")
            if loadbalancer_data is None and listeners is None and security_groups is None:
                raise ValueError(
                    "provide at least one of loadbalancer_data, listeners or security_groups"
                )
            customer_id, account_id = _identity_from_krn(lb, label="lb_krn")
            x_region = resolve_region(region)
            client = get_session().get_client()
            return sdk_raw_result(
                client.lb.with_raw_response.update_load_balancer,
                lb,
                **drop_none(
                    {
                        "k_customer_id": customer_id,
                        "x_account_id": account_id,
                        "x_region": x_region,
                        "loadbalancer_data": loadbalancer_data,
                        "listeners": listeners,
                        "security_groups": security_groups,
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_load_balancer(
        lb_krn: str,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Delete a load balancer by KRN. This is irreversible."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_load_balancer")
            ensure_confirmed(confirm, "delete_load_balancer", lb_krn)
            lb = _require_text(lb_krn, "lb_krn")
            client = get_session().get_client()
            return sdk_raw_result(
                client.lb.with_raw_response.delete_load_balancer,
                lb,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def create_target_group(
        vpc_id: str,
        target_group_name: str,
        region: Region = REGION_FIELD,
        health_monitor: Optional[dict[str, Any]] = None,
        members: Optional[list[dict[str, Any]]] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a target group in a VPC.

        health_monitor keys: delay, h_type, timeout, url_path. Each member has
        address, name, protocol_port and weight.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_target_group")
            ensure_confirmed(confirm, "create_target_group", target_group_name)
            vpc = _require_text(vpc_id, "vpc_id")
            name = _require_text(target_group_name, "target_group_name")
            x_region = resolve_region(region)
            client = get_session().get_client()
            return sdk_raw_result(
                client.lb.with_raw_response.create_target_group,
                **drop_none(
                    {
                        "x_region": x_region,
                        "vpc_id": vpc,
                        "target_group_name": name,
                        "health_monitor": health_monitor,
                        "members": members,
                        # Remove SDK Omit sentinels for unset optional fields.
                        "extra_body": {},
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def update_target_group(
        vpc_id: str,
        target_group_name: str,
        region: Region = REGION_FIELD,
        health_monitor: Optional[dict[str, Any]] = None,
        members: Optional[list[dict[str, Any]]] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Update a target group's health monitor and/or members.

        vpc_id must be the full, unmasked VPC KRN; identity is derived from it.
        members replaces the group's member list, so read it first with
        get_detailed_target_groups and send the complete desired list.
        """

        def _run() -> Any:
            ensure_writable(settings(), "update_target_group")
            ensure_confirmed(confirm, "update_target_group", target_group_name)
            vpc = _require_text(vpc_id, "vpc_id")
            name = _require_text(target_group_name, "target_group_name")
            customer_id, account_id = _identity_from_krn(vpc, label="vpc_id")
            x_region = resolve_region(region)
            client = get_session().get_client()
            return sdk_raw_result(
                client.lb.with_raw_response.update_target_group,
                **drop_none(
                    {
                        "k_customer_id": customer_id,
                        "x_account_id": account_id,
                        "x_region": x_region,
                        "vpc_id": vpc,
                        "target_group_name": name,
                        "health_monitor": health_monitor,
                        "members": members,
                        # Remove SDK Omit sentinels for unset optional fields.
                        "extra_body": {},
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_target_group(
        vpc_id: str,
        target_group_name: str,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Delete a target group. Remove it from any load balancer first."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_target_group")
            ensure_confirmed(confirm, "delete_target_group", target_group_name)
            vpc = _require_text(vpc_id, "vpc_id")
            name = _require_text(target_group_name, "target_group_name")
            client = get_session().get_client()
            return sdk_raw_result(
                client.lb.with_raw_response.delete_target_group,
                target_group_name=name,
                vpc_id=vpc,
                x_region=resolve_region(region),
            )

        return run_tool(_run)
