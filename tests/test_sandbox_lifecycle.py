"""Offline SDK wire contracts and safety checks for Sandbox lifecycle tools."""

import importlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.server import Settings as FastMCPSettings

FastMCPSettings.model_rebuild()

MODULE = "krutrim_mcp_server.tools.sandbox.lifecycle"
REGION = "In-Bangalore-1"
PREFIX = "/omni/sandbox/v1"
TEMPLATES = [
    {
        "ID": 17,
        "template_name": "python",
        "supported_services": ["sandbox"],
        "environment_variables": "SECRET=hidden",
    }
]
FLAVORS = {
    "status": 200,
    "data": [{"id": "cpu-1", "name": "cpu-small", "groupBy": {"flavorStatus": "active"}}],
}


@pytest.fixture()
def harness(monkeypatch):
    # Missing implementation is an assertion failure, not a collection error.
    try:
        spec = importlib.util.find_spec(MODULE)
    except ModuleNotFoundError:
        spec = None
    assert spec is not None, "Sandbox lifecycle implementation is missing"
    module = importlib.import_module(MODULE)
    requests = []
    replies = {}

    def handle(request):
        requests.append(request)
        reply = replies.get((request.method, request.url.path))
        assert reply is not None, f"Unexpected HTTP: {request.method} {request.url}"
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, httpx.Response):
            return reply
        status, body = reply
        return httpx.Response(status, json=body)

    http = httpx.Client(transport=httpx.MockTransport(handle))
    client = KrutrimClient(
        api_key="offline-test", base_url="https://sandbox.invalid", http_client=http, max_retries=2
    )
    state = SimpleNamespace(read_only=False, client_calls=0)

    def get_client():
        state.client_calls += 1
        return client

    session = SimpleNamespace(settings=state, get_client=get_client)
    monkeypatch.setattr(module, "get_session", lambda: session)
    monkeypatch.setattr(module, "settings", lambda: state)
    mcp = FastMCP("sandbox-test")
    module.register(mcp)
    yield SimpleNamespace(
        call=lambda tool_name, **kwargs: mcp._tool_manager.get_tool(tool_name).fn(**kwargs),
        tool=lambda name: mcp._tool_manager.get_tool(name),
        requests=requests,
        replies=replies,
        state=state,
        client=client,
    )
    client.close()


@pytest.mark.parametrize("content_type", ["application/json", "text/plain; charset=utf-8"])
def test_template_catalog_parses_json_before_redaction(harness, content_type):
    harness.replies[("GET", f"{PREFIX}/template")] = httpx.Response(
        200,
        content=json.dumps(
            [TEMPLATES[0] | {"environment_variables": "CUSTOM=opaque-template-secret"}]
        ),
        headers={"content-type": content_type},
    )
    result = harness.call("list_sandbox_templates")
    assert "opaque-template-secret" not in result.model_dump_json()
    assert isinstance(result.data, list)
    assert result.data[0]["environment_variables"] == "***REDACTED***"
    assert len(harness.requests) == 1


@pytest.mark.parametrize(
    "body",
    [
        '{"status":500,"message":"opaque-template-secret"}',
        '[{"ID":17,"description":{"secret":"opaque-template-secret"}}]',
        "not-json opaque-template-secret",
    ],
    ids=["failed-envelope", "invalid-model", "invalid-json"],
)
def test_template_catalog_rejects_unsafe_responses(harness, body):
    harness.replies[("GET", f"{PREFIX}/template")] = httpx.Response(
        200, text=body, headers={"content-type": "text/plain"}
    )
    with pytest.raises(ToolError) as error:
        harness.call("list_sandbox_templates")
    assert "opaque-template-secret" not in str(error.value)
    assert "withheld" in str(error.value)


def test_template_catalog_uses_global_endpoint_and_redacts_environment(harness):
    harness.replies[("GET", f"{PREFIX}/template")] = (200, TEMPLATES)
    result = harness.call("list_sandbox_templates")
    assert result.ok is True
    assert result.data[0]["id"] == 17
    assert result.data[0]["environment_variables"] == "***REDACTED***"
    (request,) = harness.requests
    assert not request.url.query
    assert "region" not in request.headers


@pytest.mark.parametrize(
    "tool,path,body,kwargs,query",
    [
        ("list_sandbox_flavors", "flavors", FLAVORS, {"region": REGION}, {"region": REGION}),
        (
            "list_sandboxes",
            "sandbox",
            {
                "status": 200,
                "data": {"rows": [], "total": 0, "page": 2, "limit": 3, "totalPages": 0},
            },
            {"region": REGION, "status": "active", "name": "demo", "page": 2, "limit": 3},
            {"region": REGION, "status": "active", "name": "demo", "page": "2", "limit": "3"},
        ),
    ],
)
def test_regional_read_wire_contract(harness, tool, path, body, kwargs, query):
    registered = harness.tool(tool)
    assert registered is not None, f"Missing tool: {tool}"
    assert "region" in registered.parameters["required"]
    harness.replies[("GET", f"{PREFIX}/{path}")] = (200, body)
    assert harness.call(tool, **kwargs).ok is True
    (request,) = harness.requests
    assert dict(request.url.params) == query
    assert "region" not in request.headers


@pytest.mark.parametrize(
    "tool,kwargs",
    [
        ("list_sandbox_flavors", {"region": None}),
        ("list_sandbox_flavors", {"region": " In-Bangalore-1"}),
        ("list_sandboxes", {"region": "unknown"}),
        *[("list_sandboxes", {"region": REGION, "page": v}) for v in [True, "1", 1.5, 0]],
        *[("list_sandboxes", {"region": REGION, "limit": v}) for v in [True, "10", 0, 101]],
        ("list_sandboxes", {"region": REGION, "status": "invented"}),
        ("list_sandboxes", {"region": REGION, "name": 123}),
    ],
)
def test_regional_reads_validate_before_client(harness, tool, kwargs):
    assert harness.tool(tool) is not None
    with pytest.raises(ToolError):
        harness.call(tool, **kwargs)
    assert harness.state.client_calls == 0
    assert not harness.requests


@pytest.mark.parametrize(
    "sandbox_id",
    ["76c4af0c-409d-4710-a14d-7095f636be87", "krn:sandbox:In-Bangalore-1:acct:demo", "sb.demo"],
)
def test_describe_uses_exact_id_without_region_and_redacts_environment(harness, sandbox_id):
    assert harness.tool("describe_sandbox") is not None
    body = {
        "status": 200,
        "data": {
            "id": sandbox_id,
            "status": "active",
            "environmentVariables": {"SECRET": "hidden"},
        },
    }
    harness.replies[("GET", f"{PREFIX}/sandbox/{sandbox_id}")] = (200, body)
    result = harness.call("describe_sandbox", sandbox_id=sandbox_id)
    assert result.data["data"]["id"] == sandbox_id
    assert result.data["data"]["environment_variables"] == "***REDACTED***"
    (request,) = harness.requests
    assert not request.url.query
    assert "region" not in request.headers
    assert "x-region" not in request.headers
    assert "region" not in harness.tool("describe_sandbox").parameters["properties"]


BAD_IDS = [
    "",
    " ",
    ".",
    "..",
    "../x",
    "a/b",
    "a\\b",
    "%2f",
    "a?x=1",
    "a#b",
    " a",
    "a ",
    "a b",
    "a\n",
    "a\t",
    "a\x00",
    "a\x7f",
    "a\u2003b",
    123,
    None,
]


@pytest.mark.parametrize("sandbox_id", BAD_IDS)
def test_describe_rejects_unsafe_id_before_client(harness, sandbox_id):
    assert harness.tool("describe_sandbox") is not None
    with pytest.raises(ToolError):
        harness.call("describe_sandbox", sandbox_id=sandbox_id)
    assert harness.state.client_calls == 0
    assert not harness.requests


ID_MUTATIONS = [
    ("set_sandbox_ttl", "POST", "/ttl", {"ttl_seconds": 60}),
    ("delete_sandbox", "DELETE", "", {}),
]


@pytest.mark.parametrize("tool,method,suffix,kwargs", ID_MUTATIONS)
def test_id_mutation_wire_contract_does_not_poll_or_close_client(
    harness, tool, method, suffix, kwargs
):
    assert harness.tool(tool) is not None
    sandbox_id = "krn:sandbox:In-Hyderabad-1:acct:demo"
    body = {"status": 202, "message": "accepted", "data": {"id": sandbox_id}}
    if suffix:
        body["data"]["ttlSeconds"] = 60
    harness.replies[(method, f"{PREFIX}/sandbox/{sandbox_id}{suffix}")] = (202, body)
    result = harness.call(tool, sandbox_id=sandbox_id, confirm=True, **kwargs)
    assert result.data["status"] == 202
    assert result.data["message"] == "accepted"
    (request,) = harness.requests
    assert not request.url.query
    assert "region" not in request.headers and "x-region" not in request.headers
    assert json.loads(request.content) == {"ttlSeconds": 60} if suffix else not request.content
    assert not harness.client.is_closed()
    assert harness.client.max_retries == 2


@pytest.mark.parametrize("tool,method,suffix,kwargs", ID_MUTATIONS)
@pytest.mark.parametrize(
    "read_only,confirm", [(True, True), (False, False), (False, 1), (False, "true"), (False, None)]
)
def test_id_mutation_guards_block_before_client(
    harness, tool, method, suffix, kwargs, read_only, confirm
):
    assert harness.tool(tool) is not None
    harness.state.read_only = read_only
    with pytest.raises(ToolError, match="Blocked|Refusing"):
        harness.call(tool, sandbox_id="demo", confirm=confirm, **kwargs)
    assert harness.state.client_calls == 0
    assert not harness.requests


@pytest.mark.parametrize("tool,method,suffix,kwargs", ID_MUTATIONS)
@pytest.mark.parametrize("sandbox_id", BAD_IDS)
def test_id_mutations_validate_identifiers_before_client(
    harness, tool, method, suffix, kwargs, sandbox_id
):
    assert harness.tool(tool) is not None
    with pytest.raises(ToolError):
        harness.call(tool, sandbox_id=sandbox_id, confirm=True, **kwargs)
    assert harness.state.client_calls == 0
    assert not harness.requests


@pytest.mark.parametrize("ttl", [59, 604801, True, "60", 60.0, None])
def test_set_ttl_rejects_invalid_lifetime_before_client(harness, ttl):
    assert harness.tool("set_sandbox_ttl") is not None
    with pytest.raises(ToolError):
        harness.call("set_sandbox_ttl", sandbox_id="demo", ttl_seconds=ttl, confirm=True)
    assert harness.state.client_calls == 0
    assert not harness.requests


@pytest.mark.parametrize("tool,method,suffix,kwargs", ID_MUTATIONS)
def test_id_mutations_never_retry_timeout(harness, tool, method, suffix, kwargs):
    assert harness.tool(tool) is not None
    harness.replies[(method, f"{PREFIX}/sandbox/demo{suffix}")] = httpx.ReadTimeout("timed out")
    with pytest.raises(ToolError):
        harness.call(tool, sandbox_id="demo", confirm=True, **kwargs)
    assert len(harness.requests) == 1
    assert not harness.client.is_closed()


CREATE = {
    "sandbox_name": "demo-1",
    "region": REGION,
    "flavor_name": "cpu-small",
    "ttl_seconds": 60,
    "template_id": 17,
    "confirm": True,
}


@pytest.mark.parametrize("http_status", [400, 202])
def test_create_does_not_reflect_supplied_environment_values(harness, http_status):
    prepare_create(harness)
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (
        http_status,
        {
            "status": http_status,
            "message": "echo: synthetic-private-env-value",
            "data": {"id": "sb-1"},
        },
    )
    args = CREATE | {"environment_variables": {"CUSTOM": "synthetic-private-env-value"}}
    if http_status == 400:
        with pytest.raises(ToolError) as error:
            harness.call("create_sandbox", **args)
        assert "synthetic-private-env-value" not in str(error.value)
        assert "400" in str(error.value)
    else:
        result = harness.call("create_sandbox", **args)
        assert "synthetic-private-env-value" not in json.dumps(result.data)
        assert result.data["data"]["id"] == "sb-1"


@pytest.mark.parametrize(
    "metadata",
    [
        {"groupBy": {"flavorStatus": "active", "availability": "Unavailable"}},
        {"groupBy": {"flavorStatus": "active"}, "availability": "Unavailable"},
        {"groupBy": {"flavorStatus": "active", "availability": False}},
        {"groupBy": {"flavorStatus": "active"}},
    ],
)
def test_active_flavor_ignores_availability_labels(harness, metadata):
    # Representative catalog metadata, not a captured live response.
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {"status": 200, "data": [{"name": "cpu-small", **metadata}]},
    )
    result = harness.call("create_sandbox", **CREATE)
    assert result.data["status"] == 202
    posts = [r for r in harness.requests if r.method == "POST"]
    assert len(posts) == 1
    assert json.loads(posts[0].content)["flavorName"] == "cpu-small"
    assert json.loads(posts[0].content)["region"] == REGION


@pytest.mark.parametrize("http_status", [400, 409, 503])
def test_unavailable_flavor_does_not_bypass_create_api_failure(harness, http_status):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": 200,
            "data": [
                {
                    "name": "cpu-small",
                    "groupBy": {"flavorStatus": "active"},
                    "availability": "Unavailable",
                }
            ],
        },
    )
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (
        http_status,
        {"message": "synthetic-private-backend-response"},
    )
    with pytest.raises(ToolError, match=f"HTTP {http_status}") as error:
        harness.call("create_sandbox", **CREATE)
    assert "synthetic-private-backend-response" not in str(error.value)
    assert sum(r.method == "POST" for r in harness.requests) == 1


def test_duplicate_flavors_remain_ambiguous_regardless_of_availability(harness):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": 200,
            "data": [
                {"name": "cpu-small", "groupBy": {"flavorStatus": "active"}},
                {"name": "cpu-small", "groupBy": {"flavorStatus": "inactive"}},
            ],
        },
    )
    with pytest.raises(ToolError, match="missing or ambiguous"):
        harness.call("create_sandbox", **CREATE)
    assert all(r.method == "GET" for r in harness.requests)


@pytest.mark.parametrize("flavor_status", ["active", "inactive", None])
@pytest.mark.parametrize("availability", ["Available", "Unavailable"])
def test_flavor_listing_preserves_availability_and_status_metadata(
    harness, flavor_status, availability,
):
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": 200,
            "availability": availability,
            "data": [
                {
                    "name": "sandbox-nano",
                    "groupBy": {
                        "flavorStatus": flavor_status,
                        "availability": availability,
                        "price": 1.56,
                    },
                    "availability": availability,
                    "resources": {
                        "cpu": 0.25,
                        "storage": 0.5,
                        "isAvailable": False,
                        "zones": [{"name": "zone-1", "available": False}],
                    },
                }
            ],
        },
    )
    result = harness.call("list_sandbox_flavors", region=REGION)
    entry = result.data["data"][0]
    assert result.data["status"] == 200
    assert entry["name"] == "sandbox-nano"
    assert result.data["availability"] == availability
    assert entry["availability"] == availability
    assert entry["group_by"]["availability"] == availability
    assert entry["group_by"].get("flavor_status") == flavor_status
    assert entry["group_by"]["price"] == 1.56
    assert entry["resources"] == {
        "cpu": 0.25, "storage": 0.5, "isAvailable": False,
        "zones": [{"name": "zone-1", "available": False}],
    }
    assert "snapshot" in result.data["selection_guidance"].lower()
    assert "not a guarantee" in harness.tool("list_sandbox_flavors").description.lower()
    assert len(harness.requests) == 1


@pytest.mark.parametrize(
    "region,flavor", [(REGION, "sandbox-nano"), ("In-Hyderabad-1", "sandbox-nano-hyd")]
)
@pytest.mark.parametrize("top_level", [{}, {"id": None, "name": None}])
def test_nested_flavor_name_round_trips_from_listing_to_create(harness, region, flavor, top_level):
    # Upstream SDK exposes groupBy.flavorname; this is an offline contract fixture.
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": 200,
            "data": [
                {
                    **top_level,
                    "groupBy": {"flavorname": flavor, "flavorStatus": "active"},
                    "resources": {"cpu": 0.25},
                }
            ],
        },
    )
    result = harness.call("list_sandbox_flavors", region=region)
    entry = result.data["data"][0]
    assert entry["name"] == flavor
    assert entry["id"] is None
    assert entry["group_by"]["flavorname"] == flavor
    assert entry["resources"] == {"cpu": 0.25}
    created = harness.call(
        "create_sandbox", **(CREATE | {"region": region, "flavor_name": entry["name"]})
    )
    assert created.data["status"] == 202
    posts = [r for r in harness.requests if r.method == "POST"]
    assert len(posts) == 1
    assert json.loads(posts[0].content)["flavorName"] == flavor
    assert json.loads(posts[0].content)["region"] == region
    assert all(
        dict(r.url.params) == {"region": region}
        for r in harness.requests
        if r.url.path.endswith("/flavors")
    )


def test_create_accepts_null_top_level_name_with_nested_selection(harness):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": 200,
            "data": [
                {
                    "id": None,
                    "name": None,
                    "groupBy": {"flavorname": "cpu-small", "flavorStatus": "active"},
                }
            ],
        },
    )
    assert harness.call("create_sandbox", **CREATE).data["status"] == 202
    assert sum(r.method == "POST" for r in harness.requests) == 1


@pytest.mark.parametrize("tool", ["list_sandbox_flavors", "create_sandbox"])
@pytest.mark.parametrize(
    "entry",
    [
        {"id": None, "name": None},
        {"name": None, "groupBy": {"flavorname": None}},
        {"name": None, "groupBy": {"flavorname": 123}},
        {"name": None, "groupBy": {"flavorname": " cpu-small"}},
        {"name": None, "groupBy": {"flavorname": "cpu-small\n"}},
        {"name": "", "groupBy": {"flavorname": "cpu-small"}},
        {"name": 123, "groupBy": {"flavorname": "cpu-small"}},
        {"name": "other", "groupBy": {"flavorname": "cpu-small"}},
        {"name": "cpu-small", "groupBy": {"flavorname": "other"}},
        {"name": "cpu-small", "groupBy": {"flavorname": {"secret": "opaque-catalog-secret"}}},
    ],
)
def test_flavor_name_resolution_rejects_missing_invalid_or_conflicting_names(harness, tool, entry):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (200, {"status": 200, "data": [entry]})
    args = CREATE if tool == "create_sandbox" else {"region": REGION}
    with pytest.raises(ToolError) as error:
        harness.call(tool, **args)
    assert "opaque-catalog-secret" not in str(error.value)
    assert all(r.method == "GET" for r in harness.requests)


@pytest.mark.parametrize("nested_name", ["cpu-small", None])
def test_matching_or_null_nested_name_retains_top_level_selection(harness, nested_name):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": 200,
            "data": [
                {
                    "name": "cpu-small",
                    "groupBy": {"flavorname": nested_name, "flavorStatus": "active"},
                }
            ],
        },
    )
    assert (
        harness.call("list_sandbox_flavors", region=REGION).data["data"][0]["name"] == "cpu-small"
    )
    assert harness.call("create_sandbox", **CREATE).data["status"] == 202


def test_duplicate_flavor_names_across_catalog_shapes_block_create(harness):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": 200,
            "data": [
                {"name": "cpu-small"},
                {"id": None, "name": None, "groupBy": {"flavorname": "cpu-small"}},
            ],
        },
    )
    with pytest.raises(ToolError, match="missing or ambiguous"):
        harness.call("create_sandbox", **CREATE)
    assert all(r.method == "GET" for r in harness.requests)


@pytest.mark.parametrize("status", [500, "200", True])
@pytest.mark.parametrize("tool", ["list_sandbox_flavors", "create_sandbox"])
def test_nested_flavor_names_do_not_bypass_catalog_failure(harness, status, tool):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": status,
            "message": "opaque-catalog-secret",
            "data": [{"groupBy": {"flavorname": "cpu-small"}}],
        },
    )
    with pytest.raises(ToolError) as error:
        harness.call(tool, **(CREATE if tool == "create_sandbox" else {"region": REGION}))
    assert "opaque-catalog-secret" not in str(error.value)
    assert all(r.method == "GET" for r in harness.requests)


@pytest.mark.parametrize("content_type", ["application/json", "text/plain"])
def test_nested_flavor_listing_preserves_redaction(harness, content_type):
    harness.replies[("GET", f"{PREFIX}/flavors")] = httpx.Response(
        200,
        content=json.dumps(
            {
                "status": 200,
                "data": [
                    {
                        "id": None,
                        "name": None,
                        "groupBy": {"flavorname": "cpu-small", "api_key": "opaque-catalog-secret"},
                        "environment_variables": {"CUSTOM": "opaque-catalog-secret"},
                    }
                ],
            }
        ),
        headers={"content-type": content_type},
    )
    result = harness.call("list_sandbox_flavors", region=REGION)
    assert result.data["data"][0]["name"] == "cpu-small"
    assert "opaque-catalog-secret" not in result.model_dump_json()


@pytest.mark.parametrize(
    "group",
    [
        None,
        {},
        {"flavorStatus": None},
        {"flavorStatus": "inactive"},
        {"flavorStatus": "ACTIVE"},
        {"flavorStatus": "active "},
        {"flavorStatus": "Unavailable"},
        {"flavorStatus": True},
    ],
)
@pytest.mark.parametrize("nested", [False, True])
def test_create_requires_exact_active_flavor_status(harness, group, nested):
    prepare_create(harness)
    entry: dict[str, object] = {"name": "cpu-small", "availability": "Available"}
    if group is not None:
        entry["groupBy"] = group
    if nested:
        entry["name"] = None
        entry["groupBy"] = {**(group or {}), "flavorname": "cpu-small"}
    harness.replies[("GET", f"{PREFIX}/flavors")] = (200, {"status": 200, "data": [entry]})
    with pytest.raises(ToolError):
        harness.call("create_sandbox", **CREATE)
    assert all(r.method == "GET" for r in harness.requests)


@pytest.mark.parametrize(
    "field",
    [
        "availability",
        "available",
        "isAvailable",
        "is_available",
        "flavorAvailability",
        "flavorStatus",
        "flavor_status",
    ],
)
def test_flavor_listing_preserves_capacity_field_aliases(harness, field):
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": 200,
            "data": [
                {
                    "name": "cpu-small",
                    "groupBy": {"flavorStatus": "active"},
                    "resources": {"cpu": 1, field: "Unavailable"},
                }
            ],
        },
    )
    result = harness.call("list_sandbox_flavors", region=REGION)
    assert result.data["data"][0]["resources"] == {"cpu": 1, field: "Unavailable"}


def test_listed_active_status_is_rechecked_before_create(harness):
    prepare_create(harness)
    listed = harness.call("list_sandbox_flavors", region=REGION)
    assert listed.data["data"][0]["group_by"]["flavor_status"] == "active"
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {"status": 200, "data": [{"name": "cpu-small", "groupBy": {"flavorStatus": "inactive"}}]},
    )
    with pytest.raises(ToolError, match="not marked active"):
        harness.call("create_sandbox", **CREATE)
    assert sum(r.url.path.endswith("/flavors") for r in harness.requests) == 2
    assert all(r.method == "GET" for r in harness.requests)


def test_active_selection_is_not_blocked_by_other_inactive_flavors(harness):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {
            "status": 200,
            "data": [
                {"name": "other", "groupBy": {"flavorStatus": "inactive"}},
                {
                    "name": "cpu-small",
                    "groupBy": {"flavorStatus": "active", "availability": "Unavailable"},
                },
            ],
        },
    )
    assert harness.call("create_sandbox", **CREATE).data["status"] == 202
    assert sum(r.method == "POST" for r in harness.requests) == 1


@pytest.mark.parametrize("ttl_args", [{}, {"ttl_seconds": None}])
def test_create_omits_unspecified_ttl_from_sdk_payload(harness, ttl_args):
    prepare_create(harness)
    args = {key: value for key, value in CREATE.items() if key != "ttl_seconds"} | ttl_args
    # Validate the actual MCP input model as well as the real SDK wire payload.
    validated = harness.tool("create_sandbox").fn_metadata.arg_model.model_validate(args)
    assert validated.ttl_seconds is None
    result = harness.call("create_sandbox", **args)
    assert result.data["status"] == 202
    posts = [r for r in harness.requests if r.method == "POST"]
    assert len(posts) == 1
    assert json.loads(posts[0].content) == {
        "sandboxName": "demo-1",
        "region": REGION,
        "flavorName": "cpu-small",
        "templateId": 17,
    }


@pytest.mark.parametrize("ttl", [60, 1200, 604800])
def test_create_sends_explicit_ttl_unchanged(harness, ttl):
    prepare_create(harness)
    harness.call("create_sandbox", **(CREATE | {"ttl_seconds": ttl}))
    assert json.loads(harness.requests[-1].content)["ttlSeconds"] == ttl


# Raw catalog supplied by the user; keep its lowercase keys and values intact.
CAPTURED_FLAVORS = json.loads(
    (Path(__file__).parent / "fixtures" / "sandbox_flavors_bangalore.json").read_text()
)


@pytest.mark.parametrize(
    "entry", CAPTURED_FLAVORS["data"], ids=lambda row: row["groupBy"]["flavorname"]
)
def test_captured_catalog_flavors_pass_active_preflight(harness, entry):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (200, CAPTURED_FLAVORS)
    listed = harness.call("list_sandbox_flavors", region=REGION).data
    assert len(listed["data"]) == len(CAPTURED_FLAVORS["data"]) == 5
    name = entry["groupBy"]["flavorname"]
    public = next(row for row in listed["data"] if row["name"] == name)
    assert public["group_by"]["cost"] == entry["groupBy"]["cost"]
    assert public["group_by"]["vcpus"] == entry["groupBy"]["vcpus"]
    assert public["group_by"]["storage"] == entry["groupBy"]["storage"]
    assert public["group_by"]["flavorstatus"] == entry["groupBy"]["flavorstatus"]
    assert public["group_by"].get("availability") == entry["groupBy"].get("availability")
    args = {key: value for key, value in CREATE.items() if key != "ttl_seconds"}
    result = harness.call("create_sandbox", **(args | {"flavor_name": name}))
    assert result.data["status"] == 202
    posts = [r for r in harness.requests if r.method == "POST"]
    assert len(posts) == 1
    assert json.loads(posts[0].content) == {
        "sandboxName": "demo-1",
        "region": REGION,
        "flavorName": name,
        "templateId": 17,
    }


@pytest.mark.parametrize(
    "group",
    [
        {"flavorStatus": "active", "flavorstatus": "inactive"},
        {"flavorStatus": "inactive", "flavorstatus": "active"},
        {"flavorStatus": "active", "flavorstatus": None},
        {"flavorStatus": None, "flavorstatus": "active"},
    ],
)
def test_conflicting_status_spellings_block_creation(harness, group):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {"status": 200, "data": [{"name": "cpu-small", "groupBy": group}]},
    )
    with pytest.raises(ToolError):
        harness.call("create_sandbox", **CREATE)
    assert all(r.method == "GET" for r in harness.requests)


@pytest.mark.parametrize(
    "status", [None, "inactive", "ACTIVE", "active ", True, 1, {"secret": "opaque-status-secret"}]
)
def test_lowercase_status_does_not_bypass_active_gate(harness, status):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {"status": 200, "data": [{"groupBy": {"flavorname": "cpu-small", "flavorstatus": status}}]},
    )
    with pytest.raises(ToolError) as error:
        harness.call("create_sandbox", **CREATE)
    assert "opaque-status-secret" not in str(error.value)
    assert all(r.method == "GET" for r in harness.requests)


def test_matching_status_spellings_accept_active_without_mutating_catalog(harness):
    prepare_create(harness)
    group = {"flavorname": "cpu-small", "flavorstatus": "active", "flavorStatus": "active"}
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {"status": 200, "data": [{"groupBy": group}]},
    )
    assert harness.call("create_sandbox", **CREATE).data["status"] == 202
    assert group == {"flavorname": "cpu-small", "flavorstatus": "active", "flavorStatus": "active"}
    assert sum(r.method == "POST" for r in harness.requests) == 1


def prepare_create(harness):
    harness.replies[("GET", f"{PREFIX}/template")] = (200, TEMPLATES)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (200, FLAVORS)
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (
        202,
        {
            "status": 202,
            "message": "deployment accepted",
            "data": {"id": "sb-1", "name": "demo-1", "status": "deploying", "region": REGION},
        },
    )


@pytest.mark.parametrize(
    "selection,wire_selection",
    [
        ({"template_id": 17}, {"templateId": 17}),
        ({"template_id": None, "template_name": "python"}, {"templateName": "python"}),
    ],
)
def test_create_checks_live_catalogs_and_returns_async_acceptance(
    harness, selection, wire_selection
):
    assert harness.tool("create_sandbox") is not None
    prepare_create(harness)
    result = harness.call("create_sandbox", **(CREATE | selection))
    assert result.data["status"] == 202
    assert result.data["data"]["status"] == "deploying"
    assert result.data["data"]["id"] == "sb-1"
    assert sorted((r.method, r.url.path) for r in harness.requests) == sorted(
        [
            ("GET", f"{PREFIX}/template"),
            ("GET", f"{PREFIX}/flavors"),
            ("POST", f"{PREFIX}/sandbox"),
        ]
    )
    assert harness.requests[-1].method == "POST"
    assert json.loads(harness.requests[-1].content) == {
        "sandboxName": "demo-1",
        "region": REGION,
        "flavorName": "cpu-small",
        "ttlSeconds": 60,
        **wire_selection,
    }
    flavor_request = next(r for r in harness.requests if r.url.path.endswith("/flavors"))
    assert dict(flavor_request.url.params) == {"region": REGION}
    assert not harness.client.is_closed()
    assert harness.client.max_retries == 2


@pytest.mark.parametrize(
    "read_only,confirm", [(True, True), (False, False), (False, 1), (False, "true"), (False, None)]
)
def test_create_guards_precede_catalog_client_access(harness, read_only, confirm):
    assert harness.tool("create_sandbox") is not None
    harness.state.read_only = read_only
    with pytest.raises(ToolError, match="Blocked|Refusing"):
        harness.call("create_sandbox", **(CREATE | {"confirm": confirm}))
    assert harness.state.client_calls == 0
    assert not harness.requests


@pytest.mark.parametrize(
    "overrides",
    [
        *[
            {"sandbox_name": v}
            for v in ["", "1demo", "Demo", "demo_1", "demo-", "a" * 64, " demo", "demo\n", 123]
        ],
        *[{"ttl_seconds": v} for v in [59, 604801, True, "60", 60.0]],
        *[{"template_id": v} for v in [None, True, "17", 17.0, 0, -1]],
        {"template_name": "python"},
        {"template_id": None, "template_name": ""},
        {"template_id": None, "template_name": " python"},
        {"template_id": None, "template_name": 17},
        {"flavor_name": ""},
        {"flavor_name": "cpu-small "},
        {"flavor_name": 1},
        {"region": None},
        {"region": " In-Bangalore-1"},
        {"region": "unknown"},
    ],
)
def test_create_rejects_invalid_explicit_selection_before_client(harness, overrides):
    assert harness.tool("create_sandbox") is not None
    with pytest.raises(ToolError):
        harness.call("create_sandbox", **(CREATE | overrides))
    assert harness.state.client_calls == 0
    assert not harness.requests


def test_create_never_retries_timeout_or_attempts_cleanup(harness):
    assert harness.tool("create_sandbox") is not None
    prepare_create(harness)
    harness.replies[("POST", f"{PREFIX}/sandbox")] = httpx.ReadTimeout("timed out")
    with pytest.raises(ToolError):
        harness.call("create_sandbox", **CREATE)
    assert [r.method for r in harness.requests].count("POST") == 1
    assert len(harness.requests) == 3
    assert not harness.client.is_closed()


@pytest.mark.parametrize(
    "path,catalog,selection",
    [
        ("template", [], {}),
        ("template", TEMPLATES * 2, {}),
        ("template", [{"ID": 18, "template_name": "python"}], {}),
        (
            "template",
            [{"ID": 17, "template_name": "python"}, {"ID": 18, "template_name": "python"}],
            {"template_id": None, "template_name": "python"},
        ),
        (
            "template",
            [{"ID": 17, "template_name": "Python"}],
            {"template_id": None, "template_name": "python"},
        ),
        (
            "template",
            [{"ID": 17, "template_name": "python", "supported_services": ["endpoint"]}],
            {},
        ),
        ("template", [{"ID": "17", "template_name": "python"}], {}),
        ("template", [{"ID": True, "template_name": "python"}], {}),
        (
            "template",
            [{"template_name": "python"}],
            {"template_id": None, "template_name": "python"},
        ),
        ("template", [{"ID": 17}], {}),
        ("template", {"data": TEMPLATES}, {}),
        ("template", None, {}),
        ("flavors", {"status": 200, "data": []}, {}),
        ("flavors", {"status": 200, "data": FLAVORS["data"] * 2}, {}),
        (
            "flavors",
            {"status": 200, "data": [{"name": "CPU-small", "groupBy": {"flavorStatus": "active"}}]},
            {},
        ),
        ("flavors", {"status": 200, "data": [{"groupBy": {"flavorStatus": "active"}}]}, {}),
        (
            "flavors",
            {"status": 200, "data": [{"name": 1, "groupBy": {"flavorStatus": "active"}}]},
            {},
        ),
        ("flavors", {"status": 200, "data": None}, {}),
        ("flavors", {"status": 200, "data": "malformed"}, {}),
        ("flavors", {"status": 500, "data": FLAVORS["data"]}, {}),
    ],
)
def test_create_blocks_unselectable_or_malformed_live_catalogs(harness, path, catalog, selection):
    prepare_create(harness)
    harness.replies[("GET", f"{PREFIX}/{path}")] = (200, catalog)
    with pytest.raises(ToolError):
        harness.call("create_sandbox", **(CREATE | selection))
    assert harness.requests
    assert all(r.method == "GET" for r in harness.requests)


@pytest.mark.parametrize(
    "attachments",
    [
        [
            {
                "network_storage_id": "krn:storage:acct:disk",
                "network_storage_mount_path": "/mnt/data",
            }
        ],
        [{"network_storage_id": f"disk-{i}"} for i in range(10)],
        [],
    ],
)
def test_create_optional_inputs_use_sdk_snake_case_to_wire_aliases(harness, attachments):
    prepare_create(harness)
    result = harness.call(
        "create_sandbox",
        **CREATE,
        environment_variables={"SECRET": "hidden", "EMPTY": ""},
        network_storages=attachments,
    )
    assert result.ok
    body = json.loads(harness.requests[-1].content)
    assert body["environmentVariables"] == {"SECRET": "hidden", "EMPTY": ""}
    assert body["networkStorages"] == [
        {
            "networkStorageId": item["network_storage_id"],
            **(
                {"networkStorageMountPath": item["network_storage_mount_path"]}
                if "network_storage_mount_path" in item
                else {}
            ),
        }
        for item in attachments
    ]


@pytest.mark.parametrize(
    "overrides",
    [
        {"environment_variables": {"SECRET": 123}},
        {"environment_variables": {123: "hidden"}},
        {"environment_variables": [["SECRET", "hidden"]]},
        {"environment_variables": "SECRET=hidden"},
        {"network_storages": [{"network_storage_id": "disk"}] * 11},
        {"network_storages": [{"network_storage_id": "disk", "unexpected": "hidden"}]},
        {"network_storages": [{"networkStorageId": "disk"}]},
        {"network_storages": [{"network_storage_id": "disk", "network_storage_read_only": True}]},
        {"network_storages": [{}]},
        {"network_storages": [{"network_storage_id": "bad/id"}]},
        {"network_storages": [{"network_storage_id": 17}]},
        {"network_storages": [{"network_storage_id": "disk", "network_storage_mount_path": 17}]},
        {
            "network_storages": [
                {"network_storage_id": "disk", "network_storage_mount_path": "relative"}
            ]
        },
        {
            "network_storages": [
                {"network_storage_id": "disk", "network_storage_mount_path": "/mnt/\x00"}
            ]
        },
        {"network_storages": {"network_storage_id": "disk"}},
    ],
)
def test_create_optional_input_validation_blocks_before_client(harness, overrides):
    with pytest.raises(ToolError):
        harness.call("create_sandbox", **CREATE, **overrides)
    assert harness.state.client_calls == 0
    assert not harness.requests


def test_invalid_environment_values_are_not_echoed_in_error(harness):
    with pytest.raises(ToolError) as error:
        harness.call(
            "create_sandbox",
            **CREATE,
            environment_variables={"SECRET": {"secret_value": "do-not-echo-me"}},
        )
    assert "do-not-echo-me" not in str(error.value)
    assert harness.state.client_calls == 0


@pytest.mark.parametrize("reverse", [False, True], ids=["short-first", "long-first"])
def test_create_overlapping_environment_values_fully_redacted(harness, reverse):
    prepare_create(harness)
    values = ["opaque-prefix", "opaque-prefix-private-suffix", ""]
    if reverse:
        values.reverse()
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (
        202,
        {
            "status": 202,
            "message": "opaque-prefix-private-suffix opaque-prefix",
            "data": {"id": "sb-1", "extra": [{"echo": "opaque-prefix-private-suffix"}]},
        },
    )
    result = harness.call(
        "create_sandbox",
        **CREATE,
        environment_variables={f"CUSTOM_{index}": value for index, value in enumerate(values)},
    )
    assert "opaque-prefix" not in result.model_dump_json()
    assert "private-suffix" not in result.model_dump_json()
    assert result.data["message"] == "***REDACTED*** ***REDACTED***"


def test_create_redacts_environment_echoed_by_backend(harness):
    prepare_create(harness)
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (
        202,
        {
            "status": 202,
            "data": {
                "id": "sb-1",
                "status": "deploying",
                "environmentVariables": {"SECRET": "hidden"},
            },
        },
    )
    result = harness.call("create_sandbox", **CREATE, environment_variables={"SECRET": "hidden"})
    assert "hidden" not in result.model_dump_json()
    assert "***REDACTED***" in result.model_dump_json()


def test_lifecycle_catalog_is_exactly_seven_tools(harness):
    expected = {
        "list_sandbox_templates",
        "list_sandbox_flavors",
        "list_sandboxes",
        "describe_sandbox",
        "create_sandbox",
        "set_sandbox_ttl",
        "delete_sandbox",
    }
    module = importlib.import_module(MODULE)
    mcp = FastMCP("catalog-verification")
    module.register(mcp)
    assert {tool.name for tool in mcp._tool_manager.list_tools()} == expected


def test_published_schemas_expose_required_inputs_and_bounds(harness):
    create = harness.tool("create_sandbox").parameters
    assert {"sandbox_name", "region", "flavor_name", "confirm"} <= set(create["required"])
    assert "ttl_seconds" not in create["required"]
    assert create["properties"]["sandbox_name"]["maxLength"] == 63
    ttl = create["properties"]["ttl_seconds"]
    assert ttl["default"] is None
    assert "Optional" in ttl["description"]
    assert "omitted" in ttl["description"]
    for text in ("one hour", "1 minute to 7 days", "3600"):
        assert text in ttl["description"]
        assert text in harness.tool("create_sandbox").description
    assert "1 minute to 7 days" in harness.tool("set_sandbox_ttl").description
    bounds = next(s for s in ttl["anyOf"] if s.get("type") == "integer")
    assert bounds["minimum"] == 60
    assert bounds["maximum"] == 604800
    assert {"type": "null"} in ttl["anyOf"]
    setter = harness.tool("set_sandbox_ttl").parameters
    assert "ttl_seconds" in setter["required"]
    assert setter["properties"]["ttl_seconds"]["type"] == "integer"
    assert create["properties"]["confirm"]["type"] == "boolean"
    assert create["properties"]["region"]["enum"] == ["In-Bangalore-1", "In-Hyderabad-1"]
    network = next(
        s for s in create["properties"]["network_storages"]["anyOf"] if s.get("type") == "array"
    )
    assert network["maxItems"] == 10
    model = create["$defs"]["NetworkStorageAttachment"]
    assert model["additionalProperties"] is False
    assert model["required"] == ["network_storage_id"]
    assert set(model["properties"]) == {"network_storage_id", "network_storage_mount_path"}
    for name in ["set_sandbox_ttl", "delete_sandbox"]:
        schema = harness.tool(name).parameters
        assert {"sandbox_id", "confirm"} <= set(schema["required"])
        assert "region" not in schema["properties"]
    listing = harness.tool("list_sandboxes").parameters
    assert listing["properties"]["page"]["minimum"] == 1
    assert listing["properties"]["limit"]["maximum"] == 100


@pytest.mark.parametrize(
    "tool,kwargs",
    [
        ("create_sandbox", CREATE | {"confirm": "true"}),
        ("create_sandbox", CREATE | {"confirm": 1}),
        ("create_sandbox", CREATE | {"ttl_seconds": "60"}),
        ("create_sandbox", CREATE | {"ttl_seconds": 60.0}),
        ("create_sandbox", CREATE | {"template_id": True}),
        ("create_sandbox", CREATE | {"environment_variables": {"SECRET": 123}}),
        (
            "create_sandbox",
            CREATE | {"network_storages": [{"network_storage_id": "disk", "extra": "bad"}]},
        ),
        ("set_sandbox_ttl", {"sandbox_id": "demo", "ttl_seconds": "60", "confirm": True}),
        ("delete_sandbox", {"sandbox_id": "demo", "confirm": "true"}),
        ("list_sandboxes", {"region": REGION, "page": True}),
    ],
)
def test_mcp_argument_model_rejects_coercion(harness, tool, kwargs):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        harness.tool(tool).fn_metadata.arg_model.model_validate(kwargs)
    assert harness.state.client_calls == 0


def test_creation_supports_upper_bounds_and_typed_network_attachment(harness):
    prepare_create(harness)
    module = importlib.import_module(MODULE)
    attachment = module.NetworkStorageAttachment(
        network_storage_id="disk", network_storage_mount_path="/mnt"
    )
    harness.call(
        "create_sandbox",
        **(CREATE | {"sandbox_name": "a" * 63, "ttl_seconds": 604800}),
        network_storages=[attachment],
    )
    body = json.loads(harness.requests[-1].content)
    assert body["ttlSeconds"] == 604800
    assert body["sandboxName"] == "a" * 63
    assert body["networkStorages"] == [
        {"networkStorageId": "disk", "networkStorageMountPath": "/mnt"}
    ]


def test_create_rechecks_catalog_before_every_post(harness):
    prepare_create(harness)
    harness.call("create_sandbox", **CREATE)
    harness.replies[("GET", f"{PREFIX}/flavors")] = (
        200,
        {"status": 200, "data": []},
    )
    with pytest.raises(ToolError, match="missing or ambiguous"):
        harness.call("create_sandbox", **CREATE)
    assert sum(r.method == "POST" for r in harness.requests) == 1
    assert sum(r.url.path.endswith("/flavors") for r in harness.requests) == 2


def test_list_preserves_backend_pagination_and_redacts_environment(harness):
    harness.replies[("GET", f"{PREFIX}/sandbox")] = (
        200,
        {
            "status": 200,
            "data": {
                "rows": [{"id": "sb-1", "environmentVariables": {"SECRET": "hidden"}}],
                "total": 42,
                "page": 2,
                "limit": 1,
                "totalPages": 42,
            },
        },
    )
    result = harness.call("list_sandboxes", region=REGION, page=2, limit=1)
    assert result.data["data"]["total"] == 42
    assert result.data["data"]["total_pages"] == 42
    assert result.data["data"]["page"] == 2
    assert result.data["data"]["rows"][0]["environment_variables"] == "***REDACTED***"
