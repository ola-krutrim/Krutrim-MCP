"""Guarded Sandbox lifecycle tools using the non-polling SDK API."""

from collections.abc import Callable
from typing import Annotated, Any, Literal

from krutrim_client import APIError
from krutrim_client.types.sandbox import PodTemplate
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    TypeAdapter,
    ValidationError,
)

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import (
    CONFIRM_FIELD,
    REGION_FIELD,
    Region,
    ToolSuccess,
    run_tool,
    settings,
)
from krutrim_mcp_server.tools.sandbox._responses import safe_response

SandboxID = Annotated[StrictStr, Field(min_length=1, pattern=r"^[A-Za-z0-9_:-][A-Za-z0-9_.:-]*$")]
TTL = Annotated[StrictInt, Field(ge=60, le=604800)]
SandboxName = Annotated[
    StrictStr, Field(min_length=1, max_length=63, pattern=r"^[a-z]([-a-z0-9]*[a-z0-9])?$")
]
SelectionName = Annotated[
    StrictStr,
    Field(min_length=1, pattern=r"^[^\s\x00-\x1f\x7f](?:[^\x00-\x1f\x7f]*[^\s\x00-\x1f\x7f])?$"),
]
TemplateID = Annotated[StrictInt, Field(ge=1)]
Page = Annotated[StrictInt, Field(ge=1)]
Limit = Annotated[StrictInt, Field(ge=1, le=100)]
Status = Literal["deploying", "active", "deleting", "failed_deploy"]


class NetworkStorageAttachment(BaseModel):
    """SDK-supported attachment fields; snake_case inputs, no arbitrary extras."""

    model_config = ConfigDict(extra="forbid", strict=True, revalidate_instances="always")

    network_storage_id: SandboxID
    network_storage_mount_path: (
        Annotated[StrictStr, Field(min_length=1, pattern=r"^/[^\x00-\x1f\x7f]*$")] | None
    ) = None


NetworkStorages = Annotated[list[NetworkStorageAttachment], Field(max_length=10, strict=True)]
Environment = Annotated[dict[StrictStr, StrictStr], Field(strict=True)]


class _CatalogModel(BaseModel):
    model_config = ConfigDict(strict=True)


class _Template(_CatalogModel):
    id: TemplateID = Field(alias="ID")
    template_name: SelectionName
    supported_services: list[Literal["endpoint", "aipod", "sandbox"]] | None = None


class _FlavorStatus(_CatalogModel):
    flavor_status: Literal["active", "inactive"] = Field(alias="flavorStatus")


class _Flavor(_CatalogModel):
    name: SelectionName
    group_by: _FlavorStatus = Field(alias="groupBy")


class _Flavors(_CatalogModel):
    status: StrictInt | None = None
    data: list[_Flavor]


def _require_live_selection(
    api: Any,
    region: str,
    flavor_name: str,
    template_id: int | None,
    template_name: str | None,
) -> None:
    # SDK models coerce numeric-string IDs. Validate raw SDK responses strictly
    # before trusting a catalog to authorize a chargeable operation.
    try:
        templates = TypeAdapter(list[_Template]).validate_python(
            api.with_raw_response.list_templates().json()
        )
    except ValidationError:
        raise ValueError("Malformed live Sandbox template catalog; creation blocked") from None
    matches = [
        item
        for item in templates
        if (
            item.id == template_id
            if template_id is not None
            else item.template_name == template_name
        )
    ]
    if len(matches) != 1:
        raise ValueError("Sandbox template selection is missing or ambiguous in the live catalog")
    if matches[0].supported_services is not None and "sandbox" not in matches[0].supported_services:
        raise ValueError("Selected template does not support Sandbox")
    try:
        flavors = _Flavors.model_validate(api.with_raw_response.list_flavors(region=region).json())
    except ValidationError:
        raise ValueError("Malformed live Sandbox flavor catalog; creation blocked") from None
    if flavors.status is not None and flavors.status != 200:
        raise ValueError("Live Sandbox flavor catalog did not report success")
    selected = [item for item in flavors.data if item.name == flavor_name]
    if len(selected) != 1:
        raise ValueError("Sandbox flavor selection is missing or ambiguous in the live catalog")
    if selected[0].group_by.flavor_status != "active":
        raise ValueError("Selected Sandbox flavor is not active")


def _run_lifecycle_tool(fn: Callable[[], Any]) -> ToolSuccess:
    def protected() -> Any:
        try:
            return safe_response(fn())
        except APIError as exc:
            status = getattr(exc, "status_code", None)
            detail = f"HTTP {status}" if status is not None else type(exc).__name__
            raise ValueError(
                f"Sandbox lifecycle request failed ({detail}); response details withheld. "
                "Inspect Sandbox state before retrying a mutation."
            ) from None

    return run_tool(protected)


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_sandbox_templates() -> ToolSuccess:
        """List live Sandbox templates globally; select an exact ID or name."""

        def _run() -> Any:
            # Deployed catalogs may label JSON as text/plain; typed SDK parsing
            # then returns a string, bypassing structured credential redaction.
            raw = get_session().get_client().sandbox.api.with_raw_response.list_templates()
            try:
                return TypeAdapter(list[PodTemplate]).validate_python(raw.json(), strict=True)
            except ValueError:
                raise ValueError("Invalid Sandbox template response; details withheld") from None

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def describe_sandbox(sandbox_id: SandboxID) -> ToolSuccess:
        """Read a Sandbox by its exact ID or KRN, without connecting or changing its TTL."""

        def _run() -> Any:
            TypeAdapter(SandboxID).validate_python(sandbox_id)
            return get_session().get_client().sandbox.api.retrieve(sandbox_id)

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def create_sandbox(
        sandbox_name: SandboxName,
        region: Annotated[Region, REGION_FIELD],
        flavor_name: SelectionName,
        ttl_seconds: TTL,
        confirm: Annotated[StrictBool, CONFIRM_FIELD],
        template_id: TemplateID | None = None,
        template_name: SelectionName | None = None,
        environment_variables: Environment | None = None,
        network_storages: NetworkStorages | None = None,
    ) -> ToolSuccess:
        """Request a Sandbox using an exact live template and active flavor.

        Select exactly one template_id or template_name; no template or TTL is
        inferred. A deploying/accepted result is not readiness. Use describe_sandbox
        separately to inspect progress; this tool never connects, polls, or cleans up.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_sandbox")
            ensure_confirmed(confirm, "create_sandbox", sandbox_name)
            TypeAdapter(SandboxName).validate_python(sandbox_name)
            TypeAdapter(Region).validate_python(region)
            TypeAdapter(SelectionName).validate_python(flavor_name)
            TypeAdapter(TTL).validate_python(ttl_seconds)
            TypeAdapter(TemplateID | None).validate_python(template_id)
            TypeAdapter(SelectionName | None).validate_python(template_name)
            if (template_id is None) == (template_name is None):
                raise ValueError("Select exactly one explicit template_id or template_name")
            try:
                TypeAdapter(Environment | None).validate_python(environment_variables)
            except ValidationError:
                # Pydantic error strings include input values, which may be secrets.
                raise ValueError(
                    "environment_variables must be a string-to-string object"
                ) from None
            attachments = TypeAdapter(NetworkStorages | None).validate_python(network_storages)
            api = get_session().get_client().with_options(max_retries=0).sandbox.api
            _require_live_selection(api, region, flavor_name, template_id, template_name)
            result = api.create(
                sandbox_name=sandbox_name,
                region=region,
                flavor_name=flavor_name,
                ttl_seconds=ttl_seconds,
                template_id=template_id,
                template_name=template_name,
                environment_variables=environment_variables,
                network_storages=(
                    [item.model_dump(exclude_none=True) for item in attachments]
                    if attachments is not None
                    else None
                ),
            )
            return safe_response(result, tuple((environment_variables or {}).values()))

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def set_sandbox_ttl(
        sandbox_id: SandboxID,
        ttl_seconds: TTL,
        confirm: Annotated[StrictBool, CONFIRM_FIELD],
    ) -> ToolSuccess:
        """Set a Sandbox TTL (60–604800 seconds) after explicit approval; never poll."""

        def _run() -> Any:
            ensure_writable(settings(), "set_sandbox_ttl")
            ensure_confirmed(confirm, "set_sandbox_ttl", sandbox_id)
            TypeAdapter(SandboxID).validate_python(sandbox_id)
            TypeAdapter(TTL).validate_python(ttl_seconds)
            return (
                get_session()
                .get_client()
                .with_options(max_retries=0)
                .sandbox.api.set_ttl(
                    sandbox_id,
                    ttl_seconds,
                )
            )

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def delete_sandbox(
        sandbox_id: SandboxID,
        confirm: Annotated[StrictBool, CONFIRM_FIELD],
    ) -> ToolSuccess:
        """Request deletion of the exact approved Sandbox.

        Acceptance does not mean deletion completed; inspect progress separately.
        """

        def _run() -> Any:
            ensure_writable(settings(), "delete_sandbox")
            ensure_confirmed(confirm, "delete_sandbox", sandbox_id)
            TypeAdapter(SandboxID).validate_python(sandbox_id)
            return (
                get_session()
                .get_client()
                .with_options(max_retries=0)
                .sandbox.api.delete(sandbox_id)
            )

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def list_sandbox_flavors(region: Annotated[Region, REGION_FIELD]) -> ToolSuccess:
        """List live flavors in the selected region; only active entries are selectable."""

        def _run() -> Any:
            TypeAdapter(Region).validate_python(region)
            return get_session().get_client().sandbox.api.list_flavors(region=region)

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def list_sandboxes(
        region: Annotated[Region, REGION_FIELD],
        status: Status | None = None,
        name: StrictStr | None = None,
        page: Page = 1,
        limit: Limit = 20,
    ) -> ToolSuccess:
        """List one page of Sandboxes in an explicitly selected region, preserving pagination."""

        def _run() -> Any:
            TypeAdapter(Region).validate_python(region)
            TypeAdapter(Status | None).validate_python(status)
            TypeAdapter(StrictStr | None).validate_python(name)
            TypeAdapter(Page).validate_python(page)
            TypeAdapter(Limit).validate_python(limit)
            return (
                get_session()
                .get_client()
                .sandbox.api.list(
                    region=region,
                    status=status,
                    name=name,
                    page=page,
                    limit=limit,
                )
            )

        return _run_lifecycle_tool(_run)
