"""Production MCP tool safety annotations and registration guards."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from copy import deepcopy
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Settings as FastMCPSettings
from mcp.types import ToolAnnotations
from pydantic.fields import FieldInfo

from krutrim_mcp_server.tools import ToolSuccess

_META_TOOLS = {"krutrim_ping", "list_regions"}
READ_ONLY_TOOLS = {
    "list_sandbox_templates",
    "list_sandbox_flavors",
    "list_sandboxes",
    "describe_sandbox",
    "list_sandbox_ports",
    "list_sandbox_files",
    "stat_sandbox_file",
    "read_sandbox_file",
    "describe_instance",
    "describe_instance_template",
    "describe_kks_cluster",
    "describe_kks_node_group",
    "describe_volume",
    "describe_volume_backup",
    "describe_volume_snapshot",
    "describe_vpc",
    "get_dns_zone",
    "get_iam_role",
    "get_iam_group",
    "get_iam_user",
    "get_kks_kubeconfig",
    "get_vpc_task_status",
    "krutrim_ping",
    "list_asgs",
    "list_asgs_by_vpc",
    "list_buckets",
    "list_dns_records",
    "list_dns_zones",
    "list_iam_policies",
    "list_iam_group_roles",
    "list_iam_groups",
    "list_iam_roles",
    "list_iam_user_groups",
    "list_iam_user_roles",
    "list_iam_users",
    "list_compute_flavors",
    "list_gpu_compute_flavors",
    "list_floating_ips",
    "list_images",
    "list_instances",
    "list_instance_templates",
    "list_kks_addons_catalog",
    "list_kks_cluster_addons",
    "list_kks_clusters",
    "list_kks_flavors",
    "list_kks_node_groups",
    "list_kpod_flavors",
    "list_kpod_templates",
    "list_launch_templates",
    "list_regions",
    "list_security_groups",
    "list_ssh_keys",
    "list_storage_access_keys",
    "list_subnets",
    "list_volume_backups",
    "list_volume_snapshots",
    "list_volume_types",
    "list_volumes",
    "list_vpcs",
    "plan_delete",
    "search_instances",
    "search_ports",
    "search_vpcs",
}
ADDITIVE_TOOLS = {
    "create_sandbox",
    "make_sandbox_directory",
    "add_dns_zone_vpc",
    "attach_policies_to_role",
    "attach_security_group_rule",
    "attach_volume",
    "create_and_attach_security_group_rule",
    "create_asg",
    "create_bucket",
    "create_dns_record",
    "create_dns_zone",
    "create_iam_role_with_policies",
    "create_iam_group",
    "create_iam_user",
    "create_instance",
    "create_instance_template",
    "batch_create_vms",
    "create_kks_cluster",
    "create_kks_node_group",
    "create_kpod",
    "create_launch_template",
    "create_machine_image",
    "create_port",
    "create_security_group",
    "create_security_group_rule",
    "create_ssh_key",
    "create_storage_access_key",
    "create_subnet",
    "create_volume",
    "create_volume_backup",
    "create_volume_backup_policy",
    "create_volume_snapshot",
    "create_volume_snapshot_policy",
    "create_vpc",
    "enable_programmatic_access",
    "install_kks_addon",
    "upscale_asg",
}
DESTRUCTIVE_TOOLS = {
    "set_sandbox_ttl",
    "delete_sandbox",
    "run_sandbox_command",
    "open_sandbox_port",
    "close_sandbox_port",
    "sandbox_proxy_request",
    "write_sandbox_file",
    "delete_sandbox_file",
    "move_sandbox_file",
    "assign_roles_to_user",
    "attach_floating_ip",
    "change_volume_type",
    "delete_asg",
    "delete_bucket",
    "delete_dns_record",
    "delete_dns_zone",
    "delete_floating_ip",
    "delete_iam_role",
    "delete_iam_group",
    "delete_iam_user",
    "delete_image",
    "delete_instance",
    "delete_instance_template",
    "delete_kks_addon",
    "delete_kks_cluster",
    "delete_kks_node_group",
    "delete_kpod",
    "delete_launch_template",
    "delete_machine_image",
    "delete_security_group",
    "delete_security_group_rule",
    "delete_ssh_key",
    "delete_storage_access_key",
    "delete_volume",
    "delete_volume_backup",
    "delete_volume_backup_policy",
    "delete_volume_snapshot",
    "delete_volume_snapshot_policy",
    "delete_vpc",
    "detach_floating_ip",
    "detach_security_group_rule",
    "detach_volume",
    "disable_programmatic_access",
    "downscale_asg",
    "extend_volume",
    "force_delete_volume",
    "instance_action",
    "kpod_action",
    "remove_dns_zone_vpc",
    "reset_programmatic_access",
    "restore_volume_backup",
    "update_asg",
    "update_dns_record",
    "update_launch_template",
    "update_port_security_groups",
    "update_volume",
    "update_volume_snapshot",
    "upgrade_kks_cluster",
    "upgrade_kks_node_group",
}
UNAVAILABLE_TOOLS = {
    "create_asg",
    "create_launch_template",
}


def is_read_only_tool(name: str) -> bool:
    return name in READ_ONLY_TOOLS


def is_tool_enabled(name: str) -> bool:
    """Return whether a tool is available in the unified catalog."""
    return name not in UNAVAILABLE_TOOLS


def annotations_for_tool(name: str) -> ToolAnnotations:
    read_only = is_read_only_tool(name)
    if name not in READ_ONLY_TOOLS | ADDITIVE_TOOLS | DESTRUCTIVE_TOOLS:
        raise ValueError(f"Tool {name!r} has no explicit production safety policy")
    destructive = name in DESTRUCTIVE_TOOLS
    return ToolAnnotations(
        title=name.replace("_", " ").title(),
        readOnlyHint=read_only,
        destructiveHint=destructive,
        idempotentHint=read_only,
        openWorldHint=name not in _META_TOOLS,
    )


class GuardedFastMCP(FastMCP):
    """FastMCP server that enforces safety metadata and catalog ceilings."""

    def __init__(
        self,
        *args: Any,
        server_version: str | None = None,
        **kwargs: Any,
    ) -> None:
        FastMCPSettings.model_rebuild()
        super().__init__(*args, **kwargs)
        if server_version is not None:
            self._mcp_server.version = server_version

    def tool(
        self,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | None = None,
        structured_output: bool | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        if callable(name):
            raise TypeError("Use @mcp.tool(), including parentheses")

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            if tool_name not in READ_ONLY_TOOLS | ADDITIVE_TOOLS | DESTRUCTIVE_TOOLS:
                raise ValueError(f"Tool {tool_name!r} has no explicit production safety policy")
            has_confirm = "confirm" in inspect.signature(fn).parameters
            if tool_name in READ_ONLY_TOOLS and has_confirm:
                raise ValueError(f"Read-only tool {tool_name!r} unexpectedly requires confirmation")
            if tool_name in ADDITIVE_TOOLS | DESTRUCTIVE_TOOLS and not has_confirm:
                raise ValueError(f"Mutating tool {tool_name!r} is missing confirmation")
            if not is_tool_enabled(tool_name):
                return fn

            fn.__annotations__ = dict(getattr(fn, "__annotations__", {}))
            fn.__annotations__["return"] = ToolSuccess

            signature = inspect.signature(fn)
            parameters = [
                parameter.replace(default=deepcopy(parameter.default))
                if isinstance(parameter.default, FieldInfo)
                else parameter
                for parameter in signature.parameters.values()
            ]
            fn.__signature__ = signature.replace(parameters=parameters)  # type: ignore[attr-defined]

            base_description = description or inspect.getdoc(fn) or tool_name
            if tool_name in READ_ONLY_TOOLS:
                safety_description = "Read-only; does not modify Krutrim Cloud resources."
            elif tool_name in DESTRUCTIVE_TOOLS:
                safety_description = (
                    "Destructive mutation; requires confirm=true after user review."
                )
            else:
                safety_description = "Mutation; requires confirm=true after user review."
            effective_description = f"{base_description}\n\n{safety_description}"

            base_decorator = super(GuardedFastMCP, self).tool(
                name=name,
                title=title or tool_name.replace("_", " ").title(),
                description=effective_description,
                annotations=annotations or annotations_for_tool(tool_name),
                structured_output=True if structured_output is None else structured_output,
            )
            return base_decorator(fn)

        return decorator
