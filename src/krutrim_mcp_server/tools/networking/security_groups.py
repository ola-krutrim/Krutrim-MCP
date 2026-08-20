"""Security group MCP tools."""

from typing import Annotated, Any, Optional

from pydantic import Field

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.serialize import to_jsonable
from krutrim_mcp_server.tools import (
    CONFIRM_FIELD,
    REGION_FIELD,
    Region,
    resolve_region,
    run_tool,
    settings,
)
from krutrim_mcp_server.tools.networking.rules import (
    Direction,
    EtherType,
    Port,
    Protocol,
    PublicIngressAcknowledgement,
    RuleRequestAcknowledgement,
    SecurityGroupRuleSpec,
    normalize_security_group_rule_ports,
    validate_security_group_rule,
)

Limit = Annotated[int, Field(ge=1, le=1000)]
Offset = Annotated[int, Field(ge=0)]

_RULE_ID_KEYS = {
    "id",
    "krn",
    "ruleid",
    "rulekrn",
    "securitygroupruleid",
    "securitygrouprulekrn",
}
_SECURITY_GROUP_ID_KEYS = {
    "securitygroupid",
    "securitygroupkrn",
    "securityid",
    "securitykrn",
}


def _created_rule_id(response: Any) -> str | None:
    """Find a rule identifier in direct or nested generated-client responses."""
    payload = to_jsonable(response)

    def _find(value: Any) -> str | None:
        if isinstance(value, dict):
            for key, candidate in value.items():
                normalized_key = "".join(char for char in str(key).lower() if char.isalnum())
                if normalized_key in _RULE_ID_KEYS and isinstance(candidate, str) and candidate:
                    return candidate
            for candidate in value.values():
                match = _find(candidate)
                if match:
                    return match
        elif isinstance(value, list):
            for candidate in value:
                match = _find(candidate)
                if match:
                    return match
        return None

    return _find(payload)


def _created_security_group_id(response: Any) -> str | None:
    """Find the created security-group identifier without selecting a nested rule KRN."""
    payload = to_jsonable(response)

    def _find(value: Any, keys: set[str]) -> str | None:
        if isinstance(value, dict):
            for key, candidate in value.items():
                normalized_key = "".join(char for char in str(key).lower() if char.isalnum())
                if (
                    normalized_key in keys
                    and isinstance(candidate, str)
                    and candidate
                    and ":sgr:" not in candidate
                ):
                    return candidate
            for candidate in value.values():
                match = _find(candidate, keys)
                if match:
                    return match
        elif isinstance(value, list):
            for candidate in value:
                match = _find(candidate, keys)
                if match:
                    return match
        return None

    return _find(payload, _SECURITY_GROUP_ID_KEYS) or _find(payload, {"id", "krn"})


def _create_rule(
    client: Any,
    *,
    vpc_id: str,
    direction: Direction,
    ethertype: EtherType,
    protocol: str,
    port_min: Port,
    port_max: Port,
    remote_ip_prefix: str,
    x_region: str,
) -> Any:
    port_min, port_max = normalize_security_group_rule_ports(
        protocol=protocol,
        port_min=port_min,
        port_max=port_max,
    )
    return client.securityGroup.create_rule(
        direction=direction,
        ethertypes=ethertype,
        port_max_range=port_max,
        port_min_range=port_min,
        protocol=protocol,
        remote_ip_prefix=remote_ip_prefix,
        vpcid=vpc_id,
        x_region=x_region,
    )


def _rollback_rules(
    client: Any,
    *,
    rule_ids: list[str],
    attached_rule_ids: list[str],
    security_group_id: str,
    vpc_id: str,
    x_region: str,
) -> list[str]:
    errors: list[str] = []
    for rule_id in reversed(attached_rule_ids):
        try:
            client.securityGroup.detach_rule(
                ruleid=rule_id,
                securityid=security_group_id,
                vpcid=vpc_id,
                x_region=x_region,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"detach {rule_id}: {exc}")
    for rule_id in reversed(rule_ids):
        try:
            client.securityGroup.delete_rule(rule_id, x_region=x_region)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"delete {rule_id}: {exc}")
    return errors


def _create_and_attach_rule(
    client: Any,
    *,
    security_group_id: str,
    vpc_id: str,
    direction: Direction,
    ethertype: EtherType,
    protocol: Protocol,
    port_min: Port,
    port_max: Port,
    remote_ip_prefix: str,
    x_region: str,
    rollback_security_group: bool = False,
) -> tuple[Any, Any]:
    created_rule_ids: list[str] = []
    attached_rule_ids: list[str] = []
    unidentified_rule_created = False

    try:
        created_rule = _create_rule(
            client,
            vpc_id=vpc_id,
            direction=direction,
            ethertype=ethertype,
            protocol=protocol,
            port_min=port_min,
            port_max=port_max,
            remote_ip_prefix=remote_ip_prefix,
            x_region=x_region,
        )
        rule_id = _created_rule_id(created_rule)
        if not rule_id:
            unidentified_rule_created = True
            raise ValueError("Security group rule was created but no rule id was returned.")
        created_rule_ids.append(rule_id)

        attached_rule = client.securityGroup.attach_rule(
            ruleid=rule_id,
            securityid=security_group_id,
            vpcid=vpc_id,
            x_region=x_region,
        )
        attached_rule_ids.append(rule_id)
    except Exception as operation_exc:
        rollback_errors = _rollback_rules(
            client,
            rule_ids=created_rule_ids,
            attached_rule_ids=attached_rule_ids,
            security_group_id=security_group_id,
            vpc_id=vpc_id,
            x_region=x_region,
        )
        if unidentified_rule_created:
            rollback_errors.append("a created rule returned no id and could not be deleted")
        if rollback_security_group:
            try:
                client.securityGroup.delete_security_group(
                    security_group_id,
                    x_region=x_region,
                )
            except Exception as exc:  # noqa: BLE001
                rollback_errors.append(f"delete security group {security_group_id}: {exc}")

        if rollback_errors:
            details = "; ".join(rollback_errors)
            raise RuntimeError(
                "Security group rule setup failed and rollback was incomplete; "
                f"manually inspect security group {security_group_id} and rules "
                f"{created_rule_ids}: {details}"
            ) from operation_exc
        if rollback_security_group:
            raise RuntimeError(
                "Security group rule setup failed; the newly created security group "
                "and rule were rolled back"
            ) from operation_exc
        raise RuntimeError(
            "Security group rule attachment failed; the newly created rule was rolled back"
        ) from operation_exc

    return created_rule, attached_rule


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_security_groups(
        vpc_krn: str,
        region: Region = REGION_FIELD,
        limit: Optional[Limit] = None,
        offset: Optional[Offset] = None,
    ) -> str:
        """List security groups for a VPC (pass VPC KRN identifier)."""

        def _run() -> Any:
            client = get_session().get_client()
            kwargs: dict[str, Any] = {
                "vpc_krn_identifier": vpc_krn,
                "x_region": resolve_region(region),
            }
            if limit is not None:
                kwargs["limit"] = limit
            if offset is not None:
                kwargs["offset"] = offset
            # Preserve pagination dropped by krutrim-client 0.5.x.
            kwargs["extra_query"] = {
                key: value
                for key, value in {"limit": limit, "offset": offset}.items()
                if value is not None
            }
            return client.securityGroup.list_by_vpc(**kwargs)

        return run_tool(_run)

    @mcp.tool()
    def create_security_group(
        name: str,
        description: str,
        vpc_id: str,
        rule: Optional[SecurityGroupRuleSpec] = None,
        rule_requested_by_user: RuleRequestAcknowledgement = False,
        allow_public_ingress: PublicIngressAcknowledgement = False,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """
        Create a security group, optionally creating and attaching one requested rule
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_security_group")
            ensure_confirmed(confirm, "create_security_group", name)
            if rule is None:
                if rule_requested_by_user or allow_public_ingress:
                    raise ValueError(
                        "rule_requested_by_user and allow_public_ingress require a rule"
                    )
            else:
                if rule_requested_by_user is not True:
                    raise ValueError(
                        "Creating a rule with the security group requires "
                        "rule_requested_by_user=true after the user explicitly supplies "
                        "direction, ethertype, protocol, remote_ip_prefix, and ports "
                        "unless protocol=all"
                    )
                normalized_port_min, normalized_port_max = validate_security_group_rule(
                    direction=rule.direction,
                    ethertype=rule.ethertype,
                    protocol=rule.protocol,
                    port_min=rule.port_min,
                    port_max=rule.port_max,
                    remote_ip_prefix=rule.remote_ip_prefix,
                    allow_public_ingress=allow_public_ingress,
                )

            x_region = resolve_region(region)
            client = get_session().get_client()
            created_security_group = client.securityGroup.create_security_group(
                name=name,
                description=description,
                vpcid=vpc_id,
                x_region=x_region,
            )
            if rule is None:
                return created_security_group

            security_group_id = _created_security_group_id(created_security_group)
            if not security_group_id:
                raise RuntimeError(
                    "Security group was created but no security group id was returned; "
                    f"manually inspect group {name!r} before retrying"
                )

            created_rule, attached_rule = _create_and_attach_rule(
                client,
                security_group_id=security_group_id,
                vpc_id=vpc_id,
                direction=rule.direction,
                ethertype=rule.ethertype,
                protocol=rule.protocol,
                port_min=normalized_port_min,
                port_max=normalized_port_max,
                remote_ip_prefix=rule.remote_ip_prefix,
                x_region=x_region,
                rollback_security_group=True,
            )
            return {
                "created_security_group": created_security_group,
                "security_group_id": security_group_id,
                "requested_rule": rule,
                "created_rule": created_rule,
                "attached_rule": attached_rule,
            }

        return run_tool(_run)

    @mcp.tool()
    def create_security_group_rule(
        vpc_id: str,
        direction: Direction,
        ethertype: EtherType,
        protocol: Protocol,
        remote_ip_prefix: str,
        port_min: Optional[Port] = None,
        port_max: Optional[Port] = None,
        allow_public_ingress: PublicIngressAcknowledgement = False,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """
        Create a reusable VPC security-group rule
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_security_group_rule")
            ensure_confirmed(confirm, "create_security_group_rule", vpc_id)
            normalized_port_min, normalized_port_max = validate_security_group_rule(
                direction=direction,
                ethertype=ethertype,
                protocol=protocol,
                port_min=port_min,
                port_max=port_max,
                remote_ip_prefix=remote_ip_prefix,
                allow_public_ingress=allow_public_ingress,
            )
            client = get_session().get_client()
            x_region = resolve_region(region)
            return _create_rule(
                client,
                vpc_id=vpc_id,
                direction=direction,
                ethertype=ethertype,
                protocol=protocol,
                port_min=normalized_port_min,
                port_max=normalized_port_max,
                remote_ip_prefix=remote_ip_prefix,
                x_region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def attach_security_group_rule(
        rule_id: str,
        security_group_id: str,
        vpc_id: str,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Attach an existing security group rule to a security group."""

        def _run() -> Any:
            ensure_writable(settings(), "attach_security_group_rule")
            ensure_confirmed(confirm, "attach_security_group_rule", rule_id)
            client = get_session().get_client()
            return client.securityGroup.attach_rule(
                ruleid=rule_id,
                securityid=security_group_id,
                vpcid=vpc_id,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def create_and_attach_security_group_rule(
        security_group_id: str,
        vpc_id: str,
        direction: Direction,
        ethertype: EtherType,
        protocol: Protocol,
        remote_ip_prefix: str,
        port_min: Optional[Port] = None,
        port_max: Optional[Port] = None,
        allow_public_ingress: PublicIngressAcknowledgement = False,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """
        Create and attach a security-group rule
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_and_attach_security_group_rule")
            ensure_confirmed(confirm, "create_and_attach_security_group_rule", security_group_id)
            normalized_port_min, normalized_port_max = validate_security_group_rule(
                direction=direction,
                ethertype=ethertype,
                protocol=protocol,
                port_min=port_min,
                port_max=port_max,
                remote_ip_prefix=remote_ip_prefix,
                allow_public_ingress=allow_public_ingress,
            )
            x_region = resolve_region(region)
            client = get_session().get_client()
            created_rule, attached_rule = _create_and_attach_rule(
                client,
                security_group_id=security_group_id,
                vpc_id=vpc_id,
                direction=direction,
                ethertype=ethertype,
                protocol=protocol,
                port_min=normalized_port_min,
                port_max=normalized_port_max,
                remote_ip_prefix=remote_ip_prefix,
                x_region=x_region,
            )
            return {
                "created_rule": created_rule,
                "attached_rule": attached_rule,
            }

        return run_tool(_run)

    @mcp.tool()
    def detach_security_group_rule(
        rule_id: str,
        security_group_id: str,
        vpc_id: str,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """Detach a rule from a security group."""

        def _run() -> Any:
            ensure_writable(settings(), "detach_security_group_rule")
            ensure_confirmed(confirm, "detach_security_group_rule", rule_id)
            client = get_session().get_client()
            return client.securityGroup.detach_rule(
                ruleid=rule_id,
                securityid=security_group_id,
                vpcid=vpc_id,
                x_region=resolve_region(region),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_security_group_rule(
        rule_id: str,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """Delete a security-group rule."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_security_group_rule")
            ensure_confirmed(confirm, "delete_security_group_rule", rule_id)
            client = get_session().get_client()
            client.securityGroup.delete_rule(rule_id, x_region=resolve_region(region))
            return {"deleted": True, "rule_id": rule_id}

        return run_tool(_run)

    @mcp.tool()
    def delete_security_group(
        security_group_id: str,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """Delete a security group."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_security_group")
            ensure_confirmed(confirm, "delete_security_group", security_group_id)
            client = get_session().get_client()
            client.securityGroup.delete_security_group(
                security_group_id, x_region=resolve_region(region)
            )
            return {"deleted": True, "security_group_id": security_group_id}

        return run_tool(_run)
