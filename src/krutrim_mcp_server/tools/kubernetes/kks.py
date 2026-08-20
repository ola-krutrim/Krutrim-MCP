"""KKS MCP tools."""

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.compat import sdk_raw_result, sdk_response_json
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import CONFIRM_FIELD, run_tool, settings
from krutrim_mcp_server.tools.shared.common import drop_none


class NodeScalingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    desired_size: int | None = Field(default=None, ge=0)
    min_size: int | None = Field(default=None, ge=0)
    max_size: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_bounds(self) -> "NodeScalingConfig":
        if (
            self.min_size is not None
            and self.max_size is not None
            and self.min_size > self.max_size
        ):
            raise ValueError("min_size must be less than or equal to max_size")
        if (
            self.desired_size is not None
            and self.min_size is not None
            and self.desired_size < self.min_size
        ):
            raise ValueError("desired_size must be greater than or equal to min_size")
        if (
            self.desired_size is not None
            and self.max_size is not None
            and self.desired_size > self.max_size
        ):
            raise ValueError("desired_size must be less than or equal to max_size")
        return self


class NodeRemoteAccess(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ssh_key_krn: str | None = None
    source_security_groups_krns: list[str] | None = None


class NodeRepairConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


def _model_payload(value: BaseModel | None) -> dict[str, Any] | None:
    return None if value is None else value.model_dump(exclude_none=True)


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_kks_clusters() -> str:
        """List KKS clusters."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(client.kks.clusters.with_raw_response.list)

        return run_tool(_run)

    @mcp.tool()
    def describe_kks_cluster(cluster_krn: str) -> str:
        """Describe a KKS cluster."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.kks.clusters.with_raw_response.retrieve,
                cluster_krn,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_kks_cluster(
        name: str,
        vpc_krn: str,
        subnet_krns: str,
        pod_ipv4_cidr: str,
        service_ipv4_cidr: str,
        version: Optional[str] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a KKS cluster."""

        def _run() -> Any:
            ensure_writable(settings(), "create_kks_cluster")
            ensure_confirmed(confirm, "create_kks_cluster", name)
            client = get_session().get_client()
            return sdk_raw_result(
                client.kks.clusters.with_raw_response.create,
                name=name,
                vpcKrn=vpc_krn,
                subnetKrns=subnet_krns,
                podIpv4Cidr=pod_ipv4_cidr,
                serviceIpv4Cidr=service_ipv4_cidr,
                extra_body={},
                **drop_none({"version": version}),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_kks_cluster(cluster_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete a KKS cluster."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_kks_cluster")
            ensure_confirmed(confirm, "delete_kks_cluster", cluster_krn)
            client = get_session().get_client()
            return sdk_raw_result(
                client.kks.clusters.with_raw_response.delete,
                cluster_krn,
            )

        return run_tool(_run)

    @mcp.tool()
    def get_kks_kubeconfig(cluster_krn: str) -> str:
        """Retrieve kubeconfig for a KKS cluster."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.kks.clusters.with_raw_response.retrieve_kubeconfig,
                cluster_krn,
            )

        return run_tool(_run)

    @mcp.tool()
    def upgrade_kks_cluster(
        cluster_krn: str,
        version: str,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Upgrade a KKS cluster."""

        def _run() -> Any:
            ensure_writable(settings(), "upgrade_kks_cluster")
            ensure_confirmed(confirm, "upgrade_kks_cluster", cluster_krn)
            client = get_session().get_client()
            return sdk_raw_result(
                client.kks.clusters.with_raw_response.upgrade,
                cluster_krn,
                version=version,
            )

        return run_tool(_run)

    @mcp.tool()
    def list_kks_flavors() -> str:
        """List KKS flavors."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(client.kks.with_raw_response.list_flavors)

        return run_tool(_run)

    @mcp.tool()
    def list_kks_addons_catalog() -> str:
        """List available KKS addons."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(client.kks.with_raw_response.list_addons)

        return run_tool(_run)

    @mcp.tool()
    def list_kks_node_groups(cluster_krn: str) -> str:
        """List KKS node groups for a cluster."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.kks.clusters.node_groups.with_raw_response.list,
                cluster_krn,
            )

        return run_tool(_run)

    @mcp.tool()
    def describe_kks_node_group(
        nodegroup_krn: str,
        cluster_krn: str,
    ) -> str:
        """Describe a KKS node group."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.kks.clusters.node_groups.with_raw_response.retrieve,
                nodegroup_krn,
                cluster_krn=cluster_krn,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_kks_node_group(
        cluster_krn: str,
        name: str,
        instance_types: str,
        subnets_krn: str,
        disk_size: Optional[int] = None,
        scaling_config: Optional[NodeScalingConfig] = None,
        remote_access: Optional[NodeRemoteAccess] = None,
        node_repair_config: Optional[NodeRepairConfig] = None,
        labels: Optional[dict[str, Any]] = None,
        taints: Optional[dict[str, Any]] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create a KKS node group."""

        def _run() -> Any:
            ensure_writable(settings(), "create_kks_node_group")
            ensure_confirmed(confirm, "create_kks_node_group", name)
            client = get_session().get_client()
            return sdk_raw_result(
                client.kks.clusters.node_groups.with_raw_response.create,
                cluster_krn,
                name=name,
                instance_types=instance_types,
                subnets_krn=subnets_krn,
                extra_body={},
                **drop_none(
                    {
                        "disk_size": disk_size,
                        "scaling_config": _model_payload(scaling_config),
                        "remote_access": _model_payload(remote_access),
                        "node_repair_config": _model_payload(node_repair_config),
                        "labels": labels,
                        "taints": taints,
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_kks_node_group(
        nodegroup_krn: str,
        cluster_krn: str,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Delete a KKS node group."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_kks_node_group")
            ensure_confirmed(confirm, "delete_kks_node_group", nodegroup_krn)
            client = get_session().get_client()
            return sdk_raw_result(
                client.kks.clusters.node_groups.with_raw_response.delete,
                nodegroup_krn,
                cluster_krn=cluster_krn,
            )

        return run_tool(_run)

    @mcp.tool()
    def upgrade_kks_node_group(
        nodegroup_krn: str,
        cluster_krn: str,
        scaling_config: Optional[NodeScalingConfig] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Upgrade a KKS node group."""

        def _run() -> Any:
            ensure_writable(settings(), "upgrade_kks_node_group")
            ensure_confirmed(confirm, "upgrade_kks_node_group", nodegroup_krn)
            client = get_session().get_client()
            return sdk_raw_result(
                client.kks.clusters.node_groups.with_raw_response.upgrade,
                nodegroup_krn,
                extra_body={},
                **drop_none(
                    {
                        "cluster_krn": cluster_krn,
                        "scaling_config": _model_payload(scaling_config),
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def list_kks_cluster_addons(cluster_krn: str) -> str:
        """List installed addons for a KKS cluster."""

        def _run() -> Any:
            client = get_session().get_client()
            return sdk_response_json(
                client.kks.clusters.addons.with_raw_response.list,
                cluster_krn,
            )

        return run_tool(_run)

    @mcp.tool()
    def install_kks_addon(
        cluster_krn: str,
        addon_name: str,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Install an addon on a KKS cluster."""

        def _run() -> Any:
            ensure_writable(settings(), "install_kks_addon")
            ensure_confirmed(confirm, "install_kks_addon", addon_name)
            client = get_session().get_client()
            return sdk_raw_result(
                client.kks.clusters.addons.with_raw_response.install,
                cluster_krn,
                addon_name=addon_name,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_kks_addon(
        addon_krn: str,
        cluster_krn: str,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Delete a KKS addon."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_kks_addon")
            ensure_confirmed(confirm, "delete_kks_addon", addon_krn)
            client = get_session().get_client()
            return sdk_raw_result(
                client.kks.clusters.addons.with_raw_response.delete,
                addon_krn,
                cluster_krn=cluster_krn,
            )

        return run_tool(_run)
