"""KPod MCP tools."""

import re
from typing import Annotated, Any, Literal, Optional

from pydantic import Field, StrictBool, StrictInt

from krutrim_mcp_server.adapters.kpod import list_kpod_flavors
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

_POD_NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _validate_exposed_ports(value: str, field_name: str) -> None:
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part for part in parts):
        raise ValueError(f"{field_name} must be a comma-separated list of ports")
    try:
        ports = [int(part) for part in parts]
    except ValueError as exc:
        raise ValueError(f"{field_name} must contain numeric ports") from exc
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError(f"{field_name} ports must be between 1 and 65535")


def _validate_pod_name(value: str) -> None:
    if not isinstance(value, str) or value != value.strip() or not _POD_NAME.fullmatch(value):
        raise ValueError(
            "pod_name must be 1-32 characters and contain only letters, numbers, "
            "hyphens, and underscores, with no surrounding whitespace"
        )


def _validate_create_types(
    *,
    pod_template_id: int,
    has_encrypt_volume: bool,
    has_jupyter_notebook: bool,
    has_ssh_access: bool,
) -> None:
    if isinstance(pod_template_id, bool) or not isinstance(pod_template_id, int):
        raise ValueError("pod_template_id must be an integer, not a boolean")
    feature_flags = {
        "has_encrypt_volume": has_encrypt_volume,
        "has_jupyter_notebook": has_jupyter_notebook,
        "has_ssh_access": has_ssh_access,
    }
    for field_name, value in feature_flags.items():
        if type(value) is not bool:
            raise ValueError(f"{field_name} must be a JSON boolean")


def _require_selectable_flavor(client: Any, flavor_name: str) -> None:
    catalog = list_kpod_flavors(client)
    matches = [flavor for flavor in catalog["flavors"] if flavor["create_value"] == flavor_name]
    if not matches:
        raise ValueError(
            f"KPod flavor {flavor_name!r} is not in the current live catalog; "
            "call list_kpod_flavors and select an exact create_value"
        )
    if len(matches) > 1:
        raise ValueError(
            f"KPod flavor {flavor_name!r} is ambiguous in the current live catalog; "
            "creation is blocked until the backend returns one exact create_value"
        )
    if not matches[0]["selectable"]:
        raise ValueError(
            f"KPod flavor {flavor_name!r} is not currently selectable "
            f"(status={matches[0]['status']!r}, "
            f"availability={matches[0]['availability']!r}); "
            "call list_kpod_flavors again before retrying"
        )


def register(mcp: Any) -> None:
    @mcp.tool()
    def create_kpod(
        pod_name: str,
        pod_template_id: Annotated[
            StrictInt,
            Field(
                description=(
                    "Exact live KPod template ID returned by list_kpod_templates; "
                    "never guess or substitute a template name."
                )
            ),
        ],
        flavor_name: str,
        sshkey_name: str,
        container_disk_size: str,
        volume_disk_size: str,
        volume_mount_path: str,
        expose_http_ports: str,
        expose_tcp_ports: str,
        has_jupyter_notebook: Annotated[
            StrictBool,
            Field(
                description=(
                    "Explicitly choose whether Jupyter Notebook is enabled. The Cloud "
                    "console enables it for a new KPod and uses the HTTP port for access."
                )
            ),
        ],
        has_ssh_access: Annotated[
            StrictBool,
            Field(
                description=(
                    "Explicitly choose whether SSH access is enabled. The Cloud console "
                    "enables it for a new KPod and uses the selected SSH key and TCP port."
                )
            ),
        ],
        allow_public_exposure: Annotated[
            StrictBool,
            Field(
                description=(
                    "Acknowledge that every HTTP and TCP port supplied to this tool will be "
                    "publicly exposed. Set true only after explicit user approval."
                )
            ),
        ] = False,
        has_encrypt_volume: StrictBool = True,
        environment_variables: Annotated[
            Optional[list[Any]],
            Field(
                description=(
                    "Optional pod environment variables. The backend rejects a create "
                    "request that omits this field, so an empty list is sent when no "
                    "variables are supplied."
                )
            ),
        ] = None,
        region: Region = REGION_FIELD,
        confirm: StrictBool = Field(..., description=CONFIRM_FIELD.description),
    ) -> str:
        """Create a publicly exposed KPod using the official SDK contract.

        The current SDK requires non-empty HTTP and TCP port lists and cannot
        represent a private KPod. The caller must explicitly approve that exposure.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_kpod")
            ensure_confirmed(confirm, "create_kpod", pod_name)
            if allow_public_exposure is not True:
                raise ValueError(
                    "KPod port exposure requires allow_public_exposure=true after explicit "
                    "user approval"
                )
            _validate_create_types(
                pod_template_id=pod_template_id,
                has_encrypt_volume=has_encrypt_volume,
                has_jupyter_notebook=has_jupyter_notebook,
                has_ssh_access=has_ssh_access,
            )
            _validate_pod_name(pod_name)
            _validate_exposed_ports(expose_http_ports, "expose_http_ports")
            _validate_exposed_ports(expose_tcp_ports, "expose_tcp_ports")
            client = get_session().get_client()
            _require_selectable_flavor(client, flavor_name)
            return client.kpod.pod.create(
                pod_name=pod_name,
                pod_template_id=pod_template_id,
                flavor_name=flavor_name,
                sshkey_name=sshkey_name,
                container_disk_size=container_disk_size,
                volume_disk_size=volume_disk_size,
                volume_mount_path=volume_mount_path,
                expose_http_ports=expose_http_ports,
                expose_tcp_ports=expose_tcp_ports,
                has_encrypt_volume=has_encrypt_volume,
                has_jupyter_notebook=has_jupyter_notebook,
                has_ssh_access=has_ssh_access,
                region=resolve_region(region),
                extra_body={"category": "aipod"},
                environment_variables=(
                    [] if environment_variables is None else list(environment_variables)
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def kpod_action(
        kpod_krn: str,
        action: Literal["start", "stop", "restart"],
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Start, stop, or restart a KPod."""

        def _run() -> Any:
            ensure_writable(settings(), f"kpod_action:{action}")
            ensure_confirmed(confirm, f"kpod_action:{action}", kpod_krn)
            return get_session().get_client().kpod.pod.update(kpod_krn, action=action)

        return run_tool(_run)

    @mcp.tool()
    def delete_kpod(kpod_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete a KPod."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_kpod")
            ensure_confirmed(confirm, "delete_kpod", kpod_krn)
            return get_session().get_client().kpod.pod.delete(kpod_krn)

        return run_tool(_run)
