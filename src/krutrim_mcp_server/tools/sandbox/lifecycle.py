"""Guarded Sandbox lifecycle tools using the non-polling SDK API."""

from base64 import b64encode
from collections.abc import Callable
from typing import Annotated, Any, Literal

import httpx
from krutrim_client import APIError
from krutrim_client.types.sandbox import FlavorListResponse, PodTemplate
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.serialize import _redact_scalar
from krutrim_mcp_server.tools import (
    CONFIRM_FIELD,
    REGION_FIELD,
    Region,
    ToolSuccess,
    run_tool,
    settings,
)
from krutrim_mcp_server.tools.sandbox._responses import redact_secrets, safe_response

SandboxID = Annotated[StrictStr, Field(min_length=1, pattern=r"^[A-Za-z0-9_:-][A-Za-z0-9_.:-]*$")]
TTL = Annotated[StrictInt, Field(ge=60, le=604800)]


def _zero_or_at_least_a_minute(value: int) -> int:
    if 0 < value < 60:
        raise ValueError("ttl_seconds must be 0 (never expire) or between 60 and 604800")
    return value


SetTTL = Annotated[
    StrictInt,
    Field(ge=0, le=604800),
    AfterValidator(_zero_or_at_least_a_minute),
]
SandboxName = Annotated[
    StrictStr, Field(min_length=1, max_length=28, pattern=r"^[a-z]([-a-z0-9]*[a-z0-9])?$")
]
SelectionName = Annotated[
    StrictStr,
    Field(min_length=1, pattern=r"^[^\s\x00-\x1f\x7f](?:[^\x00-\x1f\x7f]*[^\s\x00-\x1f\x7f])?$"),
]
Page = Annotated[StrictInt, Field(ge=1)]
Limit = Annotated[StrictInt, Field(ge=1, le=100)]
Status = Literal["deploying", "active", "deleting", "failed_deploy"]
_TEMPLATE_PATH = "/omni/sandbox/v1/template"
LabelKey = Annotated[StrictStr, Field(min_length=1, max_length=63, pattern=r"^[^=,]+$")]
LabelValue = Annotated[StrictStr, Field(max_length=255, pattern=r"^[^,]*$")]
Labels = Annotated[dict[LabelKey, LabelValue], Field(max_length=16, strict=True)]
ImageURI = Annotated[
    StrictStr,
    Field(min_length=1, max_length=1024, pattern=r"^[^\s\x00-\x1f\x7f]+$"),
]
LABELS_DESCRIPTION = (
    "Optional key/value labels (max 16; key 1-63 chars without '=' or ','; "
    "value up to 255 chars without ',')."
)


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


class _FlavorGroup(_CatalogModel):
    flavor_status: StrictStr | None = Field(alias="flavorStatus", default=None)

    @model_validator(mode="before")
    @classmethod
    def resolve_status_spelling(cls, value: Any) -> Any:
        # Deployed catalogs use lowercase; SDK 0.6.1 declares camelCase.
        if not isinstance(value, dict) or "flavorstatus" not in value:
            return value
        if "flavorStatus" in value and value["flavorStatus"] != value["flavorstatus"]:
            raise ValueError("Conflicting Sandbox flavor status fields")
        # Preserve the value exactly: aliases do not relax the active-only rule.
        return {**value, "flavorStatus": value["flavorstatus"]}


class _Flavor(_CatalogModel):
    name: SelectionName
    group_by: _FlavorGroup | None = Field(alias="groupBy", default=None)

    @model_validator(mode="before")
    @classmethod
    def resolve_catalog_name(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        group = value.get("groupBy")
        nested_name = group.get("flavorname") if isinstance(group, dict) else None
        if nested_name is None:
            return value
        # Never coerce, trim, or silently choose between conflicting identifiers.
        TypeAdapter(SelectionName).validate_python(nested_name)
        name = value.get("name")
        if name is not None and name != nested_name:
            raise ValueError("Conflicting Sandbox flavor names")
        return {**value, "name": nested_name}


class _Flavors(_CatalogModel):
    status: StrictInt | None = None
    data: list[_Flavor]


def _require_live_selection(
    api: Any,
    region: str,
    flavor_name: str,
) -> None:
    # SDK models coerce numeric-string IDs. Validate raw SDK responses strictly
    # before trusting a catalog to authorize a chargeable operation.
    try:
        flavors = _Flavors.model_validate(api.with_raw_response.list_flavors(region=region).json())
    except ValidationError:
        raise ValueError("Malformed live Sandbox flavor catalog; request blocked") from None
    if flavors.status is not None and flavors.status != 200:
        raise ValueError("Live Sandbox flavor catalog did not report success")
    selected = [item for item in flavors.data if item.name == flavor_name]
    if len(selected) != 1:
        raise ValueError("Sandbox flavor selection is missing or ambiguous in the live catalog")
    group = selected[0].group_by
    if group is None or group.flavor_status != "active":
        raise ValueError("Selected Sandbox flavor is not marked active; request blocked")


_SURFACED_4XX = frozenset({400, 422})
_MAX_DETAIL = 200


def _validation_detail(exc: APIError, secrets: tuple[str, ...]) -> str | None:
    """Return the backend's request-validation ``error`` text for 400/422.

    Payload-validation errors carry no resource state, so the ``error`` field
    is surfaced (redacted and bounded) to make contract problems diagnosable.
    Other statuses and other body fields keep their details withheld.
    """
    if getattr(exc, "status_code", None) not in _SURFACED_4XX:
        return None
    body = getattr(exc, "body", None)
    if not isinstance(body, dict):
        return None
    message = body.get("error")
    if not isinstance(message, str) or not message.strip():
        return None
    message = _redact_scalar(redact_secrets(message, secrets))
    message = " ".join(message.split())
    if len(message) > _MAX_DETAIL:
        message = message[:_MAX_DETAIL] + "…"
    return message


def _join_entries(values: list[str] | None, field: str, *, allow_empty: bool = False) -> str | None:
    """Validate allowlist entries and join them into the API's comma-separated form."""
    if values is None:
        return None
    entries = [str(entry).strip() for entry in values]
    if not entries:
        if allow_empty:
            return ""
        raise ValueError(f"{field} must contain at least one entry")
    for entry in entries:
        if not entry:
            raise ValueError(f"{field} entries must be non-empty strings")
        if "," in entry:
            raise ValueError(f"{field} entries must not contain commas; pass separate entries")
    return ",".join(entries)


def _network_policy_fields(
    *,
    allow_internet_access: bool | None,
    outbound_cidr_allowlist: list[str] | None,
    outbound_domain_allowlist: list[str] | None,
    inbound_cidr_allowlist: list[str] | None,
    allow_empty: bool,
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "outbound_cidr_allowlist": _join_entries(
            outbound_cidr_allowlist, "outbound_cidr_allowlist", allow_empty=allow_empty
        ),
        "outbound_domain_allowlist": _join_entries(
            outbound_domain_allowlist, "outbound_domain_allowlist", allow_empty=allow_empty
        ),
        "inbound_cidr_allowlist": _join_entries(
            inbound_cidr_allowlist, "inbound_cidr_allowlist", allow_empty=allow_empty
        ),
    }
    if allow_internet_access is not None:
        fields["allow_internet_access"] = allow_internet_access
    return {key: value for key, value in fields.items() if value is not None}


def _run_lifecycle_tool(fn: Callable[[], Any], secrets: tuple[str, ...] = ()) -> ToolSuccess:
    def protected() -> Any:
        try:
            return safe_response(fn())
        except APIError as exc:
            status = getattr(exc, "status_code", None)
            detail = f"HTTP {status}" if status is not None else type(exc).__name__
            backend = _validation_detail(exc, secrets)
            if backend is not None:
                raise ValueError(
                    f"Sandbox request rejected ({detail}): {backend}. "
                    "Fix the request before retrying."
                ) from None
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
            # Fetch the raw response directly: SDK 0.8.x wraps list_templates'
            # result, which breaks its with_raw_response variant.
            raw = get_session().get_client().get(_TEMPLATE_PATH, cast_to=httpx.Response)
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
        confirm: Annotated[StrictBool, CONFIRM_FIELD],
        ttl_seconds: Annotated[
            TTL | None,
            Field(
                description=(
                    "Optional expiry (TTL): how long the sandbox remains active. "
                    "Supported duration: 1 minute to 7 days (60–604800 seconds). "
                    "When omitted or null, ttlSeconds is not sent; the backend default "
                    "is one hour (3600 seconds)."
                )
            ),
        ] = None,
        environment_variables: Environment | None = None,
        network_storages: NetworkStorages | None = None,
        image_uri: Annotated[
            ImageURI | None,
            Field(
                description=(
                    "Optional public linux/amd64 container image (BYOC) to run instead of "
                    "the backend default. The image must bundle and start Krutrim's "
                    "sandbox-agent (port 8871/8888, user 1000, workdir /app, <=4 GiB); "
                    "stock images such as python:3.12-slim never become active. Before "
                    "using it, walk the user through the BYOC steps: "
                    "https://docs.cloud.olakrutrim.com/basics/core-infrastructure/sandbox/"
                    "bring-your-own-container-byoc"
                )
            ),
        ] = None,
        labels: Annotated[Labels | None, Field(description=LABELS_DESCRIPTION)] = None,
    ) -> ToolSuccess:
        """Request a Sandbox using an exact live flavor.

        Creation requires the selected flavor's live status (flavorstatus or
        flavorStatus) to be exactly active. Ignore separate availability labels;
        after explicit confirmation, attempt creation once. The create API decides
        provisioning acceptance, which does not guarantee readiness.
        Templates are not selectable; the backend runs its default image unless
        image_uri names a custom container image (Bring Your Own Container).
        When the user wants a custom image, instruct them through the BYOC steps
        before creating: build for linux/amd64 with Krutrim's sandbox-agent as
        the entrypoint (port 8871 or 8888, non-root user 1000, workdir /app,
        compressed size up to 4 GiB), optionally smoke-test with
        `curl http://127.0.0.1:8871/`, push to a public registry (docker.io,
        ghcr.io, public ECR; private pull secrets are unsupported), then pass
        the pushed URI. Stock images without the agent stay in deploying.
        Guide: https://docs.cloud.olakrutrim.com/basics/core-infrastructure/sandbox/bring-your-own-container-byoc
        labels attach key/value tags that list_sandboxes can filter on.
        environment_variables take plain-text values; they are base64-encoded
        on the wire as the backend requires.
        Expiry (TTL) specifies how long the sandbox remains active. The default is
        one hour (3600 seconds). Supported duration: 1 minute to 7 days
        (60–604800 seconds). Explain this expiry before requesting confirmation.
        TTL is optional: omit ttl_seconds (or pass null) to leave ttlSeconds out of
        the request and let the backend apply its default; not an indefinite lifetime.
        A deploying/accepted result is not readiness. Use describe_sandbox
        separately to inspect progress; this tool never connects, polls, or cleans up.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_sandbox")
            ensure_confirmed(confirm, "create_sandbox", sandbox_name)
            TypeAdapter(SandboxName).validate_python(sandbox_name)
            TypeAdapter(Region).validate_python(region)
            TypeAdapter(SelectionName).validate_python(flavor_name)
            TypeAdapter(TTL | None).validate_python(ttl_seconds)
            try:
                TypeAdapter(Environment | None).validate_python(environment_variables)
            except ValidationError:
                # Pydantic error strings include input values, which may be secrets.
                raise ValueError(
                    "environment_variables must be a string-to-string object"
                ) from None
            attachments = TypeAdapter(NetworkStorages | None).validate_python(network_storages)
            TypeAdapter(ImageURI | None).validate_python(image_uri)
            TypeAdapter(Labels | None).validate_python(labels)
            api = get_session().get_client().with_options(max_retries=0).sandbox.api
            _require_live_selection(api, region, flavor_name)
            result = api.create(
                sandbox_name=sandbox_name,
                region=region,
                flavor_name=flavor_name,
                ttl_seconds=ttl_seconds,
                image_uri=image_uri,
                labels=labels,
                environment_variables=encoded_env,
                network_storages=(
                    [item.model_dump(exclude_none=True) for item in attachments]
                    if attachments is not None
                    else None
                ),
            )
            return safe_response(result, env_secrets)

        plain_env = (
            environment_variables
            if isinstance(environment_variables, dict)
            and all(isinstance(v, str) for v in environment_variables.values())
            else {}
        )
        encoded_env = (
            {key: b64encode(value.encode()).decode() for key, value in plain_env.items()}
            if environment_variables is not None
            else None
        )
        env_secrets = tuple(
            secret
            for value in plain_env.values()
            for secret in (value, b64encode(value.encode()).decode())
        )
        return _run_lifecycle_tool(_run, env_secrets)

    @mcp.tool()
    def set_sandbox_ttl(
        sandbox_id: SandboxID,
        ttl_seconds: SetTTL,
        confirm: Annotated[StrictBool, CONFIRM_FIELD],
    ) -> ToolSuccess:
        """Set Sandbox expiry: 1 minute to 7 days (60–604800 seconds).

        Pass 0 to disable expiry: the Sandbox never expires on its own and keeps
        billing until it is deleted, so use 0 only with explicit approval. An
        explicit duration and approval are required; never poll.
        """

        def _run() -> Any:
            ensure_writable(settings(), "set_sandbox_ttl")
            ensure_confirmed(confirm, "set_sandbox_ttl", sandbox_id)
            TypeAdapter(SandboxID).validate_python(sandbox_id)
            TypeAdapter(SetTTL).validate_python(ttl_seconds)
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
    def set_sandbox_flavor(
        sandbox_id: SandboxID,
        flavor_name: SelectionName,
        region: Region,
        confirm: Annotated[StrictBool, CONFIRM_FIELD],
    ) -> ToolSuccess:
        """Resize a running Sandbox to another live flavor without restarting it.

        Processes and filesystem state survive. Only CPU and memory change: the
        local disk is kept, and flavors that differ in GPU are rejected. The
        Sandbox must be active. Billing continues on a new revision at the new
        flavor's rate. Call list_sandbox_flavors first and use an exact active
        flavor name; explicit approval is required and nothing is polled.
        """

        def _run() -> Any:
            ensure_writable(settings(), "set_sandbox_flavor")
            ensure_confirmed(confirm, "set_sandbox_flavor", sandbox_id)
            TypeAdapter(SandboxID).validate_python(sandbox_id)
            TypeAdapter(Region).validate_python(region)
            TypeAdapter(SelectionName).validate_python(flavor_name)
            api = get_session().get_client().with_options(max_retries=0).sandbox.api
            _require_live_selection(api, region, flavor_name)
            return safe_response(api.set_flavor(sandbox_id, flavor_name))

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def update_sandbox_network_policy(
        sandbox_id: SandboxID,
        confirm: Annotated[StrictBool, CONFIRM_FIELD],
        allow_internet_access: StrictBool | None = None,
        outbound_cidr_allowlist: list[StrictStr] | None = None,
        outbound_domain_allowlist: list[StrictStr] | None = None,
        inbound_cidr_allowlist: list[StrictStr] | None = None,
    ) -> ToolSuccess:
        """Replace the whole network policy of an active Sandbox.

        This is a full replacement: any allowlist you omit is cleared and an omitted
        allow_internet_access resets to true. To change one part and keep the rest, use
        patch_sandbox_network_policy. allow_internet_access=false blocks all traffic and
        cannot be combined with allowlists. Allowlist entries are CIDRs or domains,
        without commas. Provide at least one field; the Sandbox must be active.
        Check enforcement_status in the response; approval is required.
        """

        def _run() -> Any:
            ensure_writable(settings(), "update_sandbox_network_policy")
            ensure_confirmed(confirm, "update_sandbox_network_policy", sandbox_id)
            TypeAdapter(SandboxID).validate_python(sandbox_id)
            fields = _network_policy_fields(
                allow_internet_access=allow_internet_access,
                outbound_cidr_allowlist=outbound_cidr_allowlist,
                outbound_domain_allowlist=outbound_domain_allowlist,
                inbound_cidr_allowlist=inbound_cidr_allowlist,
                allow_empty=False,
            )
            if not fields:
                raise ValueError(
                    "provide at least one of allow_internet_access, outbound_cidr_allowlist, "
                    "outbound_domain_allowlist or inbound_cidr_allowlist"
                )
            if allow_internet_access is False and set(fields) != {"allow_internet_access"}:
                raise ValueError(
                    "allow_internet_access=false blocks all traffic and cannot be combined "
                    "with allowlists"
                )
            api = get_session().get_client().with_options(max_retries=0).sandbox.api
            return api.update_network_policy(sandbox_id, **fields)

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def patch_sandbox_network_policy(
        sandbox_id: SandboxID,
        confirm: Annotated[StrictBool, CONFIRM_FIELD],
        allow_internet_access: StrictBool | None = None,
        outbound_cidr_allowlist: list[StrictStr] | None = None,
        outbound_domain_allowlist: list[StrictStr] | None = None,
        inbound_cidr_allowlist: list[StrictStr] | None = None,
        add_outbound_domains: list[StrictStr] | None = None,
        remove_outbound_domains: list[StrictStr] | None = None,
    ) -> ToolSuccess:
        """Partially update the network policy of an active Sandbox.

        Only the fields you pass change; everything else is preserved. A list replaces
        that allowlist, and an empty list clears it. add_outbound_domains and
        remove_outbound_domains edit the outbound domain allowlist incrementally.
        allow_internet_access=false blocks all traffic and cannot be combined with
        allowlists. Provide at least one field; check enforcement_status in the
        response; approval is required.
        """

        def _run() -> Any:
            ensure_writable(settings(), "patch_sandbox_network_policy")
            ensure_confirmed(confirm, "patch_sandbox_network_policy", sandbox_id)
            TypeAdapter(SandboxID).validate_python(sandbox_id)
            fields = _network_policy_fields(
                allow_internet_access=allow_internet_access,
                outbound_cidr_allowlist=outbound_cidr_allowlist,
                outbound_domain_allowlist=outbound_domain_allowlist,
                inbound_cidr_allowlist=inbound_cidr_allowlist,
                allow_empty=True,
            )
            for name, values in (
                ("add_outbound_domains", add_outbound_domains),
                ("remove_outbound_domains", remove_outbound_domains),
            ):
                if values is not None:
                    _join_entries(values, name)
                    fields[name] = [entry.strip() for entry in values]
            if not fields:
                raise ValueError("provide at least one field to change")
            if allow_internet_access is False and set(fields) != {"allow_internet_access"}:
                raise ValueError(
                    "allow_internet_access=false blocks all traffic and cannot be combined "
                    "with allowlists or domain edits"
                )
            api = get_session().get_client().with_options(max_retries=0).sandbox.api
            return api.patch_network_policy(sandbox_id, **fields)

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def delete_sandbox(
        sandbox_id: SandboxID,
        confirm: Annotated[StrictBool, CONFIRM_FIELD],
    ) -> ToolSuccess:
        """Request deletion of the exact approved Sandbox.

        Acceptance does not mean deletion completed; inspect progress separately.
        Deletion is asynchronous: the sandbox can still appear in list_sandboxes
        briefly afterwards. Re-check later rather than retrying the delete.
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
        """List flavor names, resources, and pricing in the selected region.

        Names come from name or groupBy.flavorname; a missing/null flavor ID is
        valid because creation uses the exact name, not an ID.
        Display the backend-reported availability and flavor status when present.
        These fields are a live snapshot, not a guarantee of capacity or eligibility.
        Missing fields mean unknown availability, not available or unavailable.
        create_sandbox independently rechecks the live catalog for active status
        (flavorstatus or flavorStatus) and attempts provisioning once after explicit
        confirmation; report its actual result, not an inferred error.
        """

        def _run() -> Any:
            TypeAdapter(Region).validate_python(region)
            raw = (
                get_session().get_client().sandbox.api.with_raw_response.list_flavors(region=region)
            )
            try:
                body = raw.json()
                if not isinstance(body, dict):
                    raise ValueError("Expected a Sandbox flavor catalog object")
                catalog = _Flavors.model_validate(body)
                # Share preflight name resolution while preserving SDK output
                # fields, aliases, metadata, and structured secret redaction.
                normalized = {
                    **body,
                    "data": [
                        {**item, "name": flavor.name}
                        for item, flavor in zip(body["data"], catalog.data, strict=True)
                    ],
                }
                response = FlavorListResponse.model_validate(normalized, strict=True)
                # Check the original envelope and redact secrets before shaping
                # display data. Creation always re-reads the unfiltered catalog.
                public_catalog = safe_response(response)
                # SDK 0.6.2 reshaped the flavor model: groupBy.flavor_status
                # became a non-serialized property and the top-level id field
                # was dropped. Preserve the published output contract so
                # existing callers keep working on both SDK versions.
                for entry in public_catalog.get("data") or []:
                    if isinstance(entry, dict):
                        entry.setdefault("id", None)
                        group = entry.get("group_by")
                        if isinstance(group, dict) and group.get("flavor_status") is None:
                            group["flavor_status"] = (
                                group.get("flavorstatus")
                                if group.get("flavorstatus") is not None
                                else group.get("flavorStatus")
                            )
                public_catalog["selection_guidance"] = (
                    "Backend-reported availability and flavor status are a live snapshot, "
                    "not a guarantee of capacity. Missing fields mean unknown availability. "
                    "Use an exact listed name with create_sandbox after explicit confirmation; "
                    "that tool rechecks active status in the live catalog and returns the "
                    "actual provisioning outcome."
                )
                return public_catalog
            except ValueError:
                raise ValueError("Invalid Sandbox flavor response; details withheld") from None

        return _run_lifecycle_tool(_run)

    @mcp.tool()
    def list_sandboxes(
        region: Annotated[Region, REGION_FIELD],
        status: Status | None = None,
        name: StrictStr | None = None,
        page: Page = 1,
        limit: Limit = 20,
        labels: Annotated[
            Labels | None,
            Field(description="Optional label filter; only sandboxes matching every pair."),
        ] = None,
    ) -> ToolSuccess:
        """List one page of Sandboxes in an explicitly selected region, preserving pagination.

        Optionally filter by name, status, or labels set at creation.
        """

        def _run() -> Any:
            TypeAdapter(Region).validate_python(region)
            TypeAdapter(Status | None).validate_python(status)
            TypeAdapter(StrictStr | None).validate_python(name)
            TypeAdapter(Page).validate_python(page)
            TypeAdapter(Limit).validate_python(limit)
            TypeAdapter(Labels | None).validate_python(labels)
            return (
                get_session()
                .get_client()
                .sandbox.api.list(
                    region=region,
                    status=status,
                    name=name,
                    labels=labels,
                    page=page,
                    limit=limit,
                )
            )

        return _run_lifecycle_tool(_run)
