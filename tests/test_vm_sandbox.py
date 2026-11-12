"""Offline wire contracts and guards for the VM Sandbox (/sandbox/v1) tools."""

import importlib
import json
from types import SimpleNamespace

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.server import Settings as FastMCPSettings

from krutrim_mcp_server.adapters import vm_sandbox as adapter
from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server
from krutrim_mcp_server.tools.sandbox import lifecycle as sandbox_lifecycle

FastMCPSettings.model_rebuild()

REGION = "In-Hyderabad-1"
PREFIX = "/sandbox/v1"
KRN = "krn:vm-sandbox:In-Hyderabad-1:acct:cust:demo"
FLAVOR = "sandbox-medium-hyd"
MODULES = (
    "krutrim_mcp_server.tools.vm_sandbox.lifecycle",
    "krutrim_mcp_server.tools.vm_sandbox.templates",
    "krutrim_mcp_server.tools.vm_sandbox.operations",
    "krutrim_mcp_server.tools.vm_sandbox.network",
    "krutrim_mcp_server.tools.vm_sandbox.execution",
    "krutrim_mcp_server.tools.vm_sandbox.access",
)
VM_TOOLS = {
    "list_vm_sandboxes",
    "describe_vm_sandbox",
    "list_vm_sandbox_flavors",
    "create_vm_sandbox",
    "delete_vm_sandbox",
    "start_vm_sandbox",
    "stop_vm_sandbox",
    "extend_vm_sandbox_ttl",
    "resize_vm_sandbox",
    "get_vm_sandbox_usage",
    "list_vm_sandbox_templates",
    "describe_vm_sandbox_template",
    "create_vm_sandbox_template",
    "delete_vm_sandbox_template",
    "get_vm_sandbox_operation",
    "wait_vm_sandbox_operation",
    "get_vm_sandbox_network",
    "update_vm_sandbox_network",
    "exec_vm_sandbox",
    "create_vm_sandbox_command",
    "list_vm_sandbox_commands",
    "get_vm_sandbox_command",
    "kill_vm_sandbox_command",
    "expose_vm_sandbox_port",
    "list_vm_sandbox_ports",
    "close_vm_sandbox_port",
    "read_vm_sandbox_file",
    "write_vm_sandbox_file",
    "create_vm_sandbox_terminal_ticket",
}


def _flavor_body(name=FLAVOR, vcpus=1, ram=2, total=1):
    return {
        "code": "ok",
        "details": {
            "total": total,
            "limit": 200,
            "offset": 0,
            "flavors": [
                {
                    "id": "fl-1",
                    "name": name,
                    "vcpus": vcpus,
                    "ram_gib": ram,
                    "local_disk_gib": 20,
                    "cost": 1.5,
                    "currency": "INR",
                    "unit": "hour",
                    "region": REGION,
                }
            ],
        },
    }


def _sandbox_body():
    return {
        "code": "ok",
        "message": "accepted",
        "details": {
            "krn_id": KRN,
            "name": "demo",
            "status": "PROVISIONING",
            "operation_id": "op-1",
            "env": ["GREETING"],
        },
    }


def _templates(items, total=None):
    return {
        "code": "ok",
        "details": {
            "default": "base",
            "total": len(items) if total is None else total,
            "limit": 200,
            "offset": 0,
            "templates": items,
        },
    }


@pytest.fixture()
def harness(monkeypatch):
    requests = []
    replies = {}

    def handle(request):
        requests.append(request)
        reply = replies.get((request.method, request.url.path))
        assert reply is not None, f"Unexpected HTTP: {request.method} {request.url}"
        if isinstance(reply, list):
            assert reply, f"No more replies for {request.method} {request.url.path}"
            reply = reply.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, httpx.Response):
            return reply
        status, body = reply
        return httpx.Response(status, json=body)

    http = httpx.Client(transport=httpx.MockTransport(handle))
    client = KrutrimClient(
        api_key="offline-test",
        base_url="https://sandbox.invalid",
        http_client=http,
        max_retries=2,
    )
    state = SimpleNamespace(read_only=False, client_calls=0)

    def get_client():
        state.client_calls += 1
        return client

    session = SimpleNamespace(settings=state, get_client=get_client)
    mcp = FastMCP("vm-sandbox-test")
    for name in MODULES:
        module = importlib.import_module(name)
        monkeypatch.setattr(module, "get_session", lambda session=session: session)
        if hasattr(module, "settings"):
            monkeypatch.setattr(module, "settings", lambda state=state: state)
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


def _prepare_flavor(harness, **flavor):
    harness.replies[("GET", f"{PREFIX}/flavors")] = (200, _flavor_body(**flavor))


def _json(request):
    return json.loads(request.content)


def _header(request, name):
    return request.headers.get(name)


@pytest.mark.parametrize(
    "image",
    [
        "ubuntu:24.04",
        "library/ubuntu:24.04",
        "docker.io/library/ubuntu:24.04",
        "ghcr.io/org/app:1.2.3",
        "quay.io/org/app",
        "public.ecr.aws/org/app:latest",
        "gcr.io/project/app:tag",
        "registry.k8s.io/pause:3.10",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        "registry.gitlab.com/group/project:tag",
        "ubuntu@sha256:" + "a" * 64,
    ],
)
def test_public_image_references_are_accepted(image):
    assert adapter.validate_image(image) == image


@pytest.mark.parametrize(
    "image",
    [
        "",
        "a" * 256,
        "http://docker.io/library/ubuntu",
        "evil.example/ubuntu:24.04",
        "localhost/ubuntu",
        "Ubuntu:24.04",
        "ubuntu:bad tag",
        "ghcr.io/Org/app",
    ],
)
def test_image_references_outside_the_console_rules_are_rejected(image):
    with pytest.raises(ValueError):
        adapter.validate_image(image)


@pytest.mark.parametrize(
    "destination",
    ["example.com", "*.example.com", "10.1.2.3", "10.0.0.0/8", "0.0.0.0/0"],
)
def test_egress_destinations_match_the_console_rules(destination):
    assert adapter.validate_destination(destination) == destination


@pytest.mark.parametrize(
    "destination",
    ["http://example.com", "example.com:443", "2001:db8::1", "2001:db8::/32", "", " *.example.com"],
)
def test_egress_destinations_reject_urls_ports_and_ipv6(destination):
    with pytest.raises(ValueError):
        adapter.validate_destination(destination)


def test_vm_sandbox_catalog_is_separate_from_sandbox(harness):
    assert {harness.tool(name).name for name in VM_TOOLS} == VM_TOOLS
    assert sandbox_lifecycle._TEMPLATE_PATH == "/omni/sandbox/v1/template"
    for name in (
        "list_sandboxes",
        "create_sandbox",
        "run_sandbox_command",
        "open_sandbox_port",
    ):
        assert harness.tool(name) is None


def test_server_registers_vm_sandbox_without_removing_sandbox_tools():
    server = create_server(
        Settings(
            api_key="test-api-key-for-offline-tests",
            base_url="https://cloud.olakrutrim.com",
            default_region="In-Bangalore-1",
            read_only=False,
            log_level="ERROR",
            client_max_retries=0,
        )
    )
    names = {tool.name for tool in server._tool_manager.list_tools()}
    assert VM_TOOLS <= names
    assert {
        "list_sandboxes",
        "create_sandbox",
        "run_sandbox_command",
        "list_sandbox_flavors",
    } <= names
    assert len(names) == 216
    assert "VM Sandbox is a separate product" in server.instructions
    assert "VM Sandbox is only available in In-Hyderabad-1" in server.instructions
    assert "/sandbox/v1" in server.instructions
    assert "/omni/sandbox/v1" in server.instructions
    create = server._tool_manager.get_tool("create_vm_sandbox")
    assert {"name", "region", "flavor", "confirm"} <= set(create.parameters["required"])
    region_schema = create.parameters["properties"]["region"]
    assert region_schema.get("const") == "In-Hyderabad-1" or region_schema.get("enum") == [
        "In-Hyderabad-1"
    ]
    assert "only available in In-Hyderabad-1" in region_schema["description"]
    assert "template" not in create.parameters["required"]
    assert "ttl_seconds" not in create.parameters["required"]
    assert "one hour" in create.description
    assert "startup-script" in create.description
    assert create.annotations.readOnlyHint is False
    listed = server._tool_manager.get_tool("list_vm_sandboxes")
    waiting = server._tool_manager.get_tool("wait_vm_sandbox_operation")
    assert listed.annotations.readOnlyHint is True
    assert waiting.annotations.readOnlyHint is True


def test_list_and_describe_use_vm_sandbox_paths(harness):
    harness.replies[("GET", f"{PREFIX}/sandboxes")] = (
        200,
        _sandbox_body() | {"details": {"sandboxes": []}},
    )
    harness.replies[("GET", f"{PREFIX}/sandboxes/{KRN}")] = (200, _sandbox_body())
    listed = harness.call(
        "list_vm_sandboxes",
        region=REGION,
        status="ACTIVE",
        name="demo",
        limit=20,
        offset=0,
    )
    assert listed.ok is True
    described = harness.call("describe_vm_sandbox", krn_id=KRN, region=REGION)
    assert described.data["details"]["krn_id"] == KRN
    listing, describe = harness.requests
    assert dict(listing.url.params) == {
        "limit": "20",
        "offset": "0",
        "status": "ACTIVE",
        "name": "demo",
    }
    assert _header(listing, "x-region") == REGION
    assert "idempotency-key" not in {key.lower() for key in listing.headers}
    assert describe.url.path == f"{PREFIX}/sandboxes/{KRN}"
    assert all("/omni/sandbox/" not in request.url.path for request in harness.requests)


def test_create_checks_the_live_flavor_then_posts_the_console_body(harness):
    _prepare_flavor(harness)
    harness.replies[("POST", f"{PREFIX}/sandboxes")] = (200, _sandbox_body())
    result = harness.call(
        "create_vm_sandbox",
        name="demo",
        region=REGION,
        flavor=FLAVOR,
        confirm=True,
        template="base",
        ttl_seconds=120,
        env={"GREETING": "namaste"},
        network={"egress": {"default_action": "deny", "allow": ["example.com", "10.0.0.0/8"]}},
        idempotency_key="create-demo-1",
    )
    assert result.ok is True
    assert "namaste" not in result.model_dump_json()
    flavor_request, create_request = harness.requests
    assert flavor_request.url.path == f"{PREFIX}/flavors"
    assert dict(flavor_request.url.params) == {"limit": "200", "offset": "0"}
    assert _json(create_request) == {
        "name": "demo",
        "flavor": FLAVOR,
        "template": "base",
        "ttl_seconds": 120,
        "env": {"GREETING": "namaste"},
        "network": {"egress": {"default_action": "deny", "allow": ["example.com", "10.0.0.0/8"]}},
    }
    assert _header(create_request, "x-region") == REGION
    assert _header(create_request, "idempotency-key") == "create-demo-1"
    assert create_request.headers["content-type"].startswith("application/json")


def test_create_omits_optional_fields_and_generates_an_idempotency_key(harness):
    _prepare_flavor(harness)
    harness.replies[("POST", f"{PREFIX}/sandboxes")] = (200, _sandbox_body())
    harness.call(
        "create_vm_sandbox",
        name="demo",
        region=REGION,
        flavor=FLAVOR,
        confirm=True,
    )
    body = _json(harness.requests[-1])
    assert body == {"name": "demo", "flavor": FLAVOR}
    key = _header(harness.requests[-1], "idempotency-key")
    assert key and " " not in key


@pytest.mark.parametrize(
    "kwargs",
    [
        {"template": "base", "image": "ubuntu:24.04"},
        {"image": "evil.example/app:latest"},
        {"env": {"KRUTRIM_TOKEN": "x"}},
        {"env": {"SPACE_TOKEN": "x"}},
        {"ttl_seconds": 0},
        {"ttl_seconds": 30},
        {"ttl_seconds": 604801},
        {"name": "-demo"},
        {"flavor": "missing-flavor"},
        {"network": {"egress": {"default_action": "deny", "allow": ["http://example.com"]}}},
        {"idempotency_key": "has space"},
        {"region": "In-Hyderabad-2"},
    ],
)
def test_create_rejects_invalid_input_before_posting(harness, kwargs):
    kwargs = dict(kwargs)
    _prepare_flavor(harness)
    harness.replies[("POST", f"{PREFIX}/sandboxes")] = (200, _sandbox_body())
    with pytest.raises(ToolError):
        harness.call(
            "create_vm_sandbox",
            name=kwargs.pop("name", "demo"),
            region=kwargs.pop("region", REGION),
            flavor=kwargs.pop("flavor", FLAVOR),
            confirm=True,
            **kwargs,
        )
    assert all(request.method != "POST" for request in harness.requests)


def test_create_rejects_flavors_above_the_platform_limit(harness):
    _prepare_flavor(harness, vcpus=8, ram=16)
    with pytest.raises(ToolError, match="4 vCPU"):
        harness.call(
            "create_vm_sandbox",
            name="demo",
            region=REGION,
            flavor=FLAVOR,
            confirm=True,
        )
    assert [request.method for request in harness.requests] == ["GET"]


def test_create_redacts_validation_errors_that_echo_env_values(harness):
    _prepare_flavor(harness)
    harness.replies[("POST", f"{PREFIX}/sandboxes")] = httpx.Response(
        400,
        json={"message": "rejected secret-value in env"},
    )
    with pytest.raises(ToolError) as error:
        harness.call(
            "create_vm_sandbox",
            name="demo",
            region=REGION,
            flavor=FLAVOR,
            confirm=True,
            env={"TOKEN": "secret-value"},
        )
    assert "secret-value" not in str(error.value)
    assert "rejected" in str(error.value)


def test_mutations_require_confirmation_and_honor_read_only(harness):
    _prepare_flavor(harness)
    with pytest.raises(ToolError, match="confirm=true"):
        harness.call(
            "create_vm_sandbox",
            name="demo",
            region=REGION,
            flavor=FLAVOR,
            confirm=False,
        )
    harness.state.read_only = True
    with pytest.raises(ToolError, match="KRUTRIM_MCP_READ_ONLY"):
        harness.call(
            "delete_vm_sandbox",
            krn_id=KRN,
            region=REGION,
            confirm=True,
        )
    assert harness.requests == []


def test_masked_krn_is_rejected_before_http(harness):
    with pytest.raises(ToolError, match=r":\*\*\*:"):
        harness.call(
            "describe_vm_sandbox",
            krn_id="krn:vm-sandbox:In-Hyderabad-1:***:cust:demo",
            region=REGION,
        )
    assert harness.requests == []


def test_bangalore_and_other_regions_are_rejected_for_vm_sandbox(harness):
    for region in ("In-Bangalore-1", "In-Hyderabad-2", "us-east-1", ""):
        with pytest.raises(ToolError, match="VM Sandbox is only available in In-Hyderabad-1"):
            harness.call("list_vm_sandboxes", region=region)
    assert harness.requests == []


def test_vm_sandbox_region_limit_does_not_change_other_services():
    from typing import get_args

    from krutrim_mcp_server.config import KNOWN_REGIONS
    from krutrim_mcp_server.tools import Region

    assert KNOWN_REGIONS == ("In-Bangalore-1", "In-Hyderabad-1")
    assert get_args(Region) == ("In-Bangalore-1", "In-Hyderabad-1")
    assert adapter.VM_SANDBOX_REGIONS == ("In-Hyderabad-1",)


@pytest.mark.parametrize(
    "tool,path,method",
    [
        ("start_vm_sandbox", f"{PREFIX}/sandboxes/{KRN}/start", "POST"),
        ("stop_vm_sandbox", f"{PREFIX}/sandboxes/{KRN}/stop", "POST"),
        ("delete_vm_sandbox", f"{PREFIX}/sandboxes/{KRN}", "DELETE"),
    ],
)
def test_power_and_delete_return_before_the_operation_finishes(harness, tool, path, method):
    harness.replies[(method, path)] = (200, _sandbox_body())
    result = harness.call(tool, krn_id=KRN, region=REGION, confirm=True)
    assert result.data["details"]["operation_id"] == "op-1"
    request = harness.requests[-1]
    assert request.method == method
    assert request.url.path == path
    assert _header(request, "x-region") == REGION
    assert _header(request, "idempotency-key")


def test_extend_adds_a_duration_and_resize_rechecks_the_flavor(harness):
    harness.replies[("POST", f"{PREFIX}/sandboxes/{KRN}/extend")] = (200, _sandbox_body())
    _prepare_flavor(harness, name="sandbox-large-hyd", vcpus=2, ram=4)
    harness.replies[("POST", f"{PREFIX}/sandboxes/{KRN}/resize")] = (200, _sandbox_body())
    harness.call(
        "extend_vm_sandbox_ttl",
        krn_id=KRN,
        region=REGION,
        ttl_seconds=3600,
        confirm=True,
    )
    harness.call(
        "resize_vm_sandbox",
        krn_id=KRN,
        region=REGION,
        flavor="sandbox-large-hyd",
        confirm=True,
    )
    assert _json(harness.requests[0]) == {"ttl_seconds": 3600}
    assert _json(harness.requests[-1]) == {"flavor": "sandbox-large-hyd"}


def test_usage_flavors_and_templates_are_region_scoped_reads(harness):
    harness.replies[("GET", f"{PREFIX}/sandboxes/{KRN}/usage")] = (
        200,
        {"code": "ok", "details": {"krn_id": KRN, "running_seconds": 5}},
    )
    harness.replies[("GET", f"{PREFIX}/flavors")] = (200, _flavor_body())
    harness.replies[("GET", f"{PREFIX}/templates")] = (
        200,
        _templates([{"id": "base", "krn_id": "krn:template:base", "default_template": True}]),
    )
    harness.call("get_vm_sandbox_usage", krn_id=KRN, region=REGION)
    harness.call("list_vm_sandbox_flavors", region=REGION)
    harness.call("list_vm_sandbox_templates", region=REGION)
    assert [request.url.path for request in harness.requests] == [
        f"{PREFIX}/sandboxes/{KRN}/usage",
        f"{PREFIX}/flavors",
        f"{PREFIX}/templates",
    ]
    assert all(_header(request, "x-region") == REGION for request in harness.requests)


def test_template_build_enforces_custom_limits_then_posts(harness):
    platform = [
        {
            "id": name,
            "default_template": True,
            "custom": False,
            "status": "READY",
        }
        for name in ("base", "hermes-python", "node", "python")
    ]
    harness.replies[("GET", f"{PREFIX}/templates")] = (200, _templates(platform))
    harness.replies[("POST", f"{PREFIX}/templates")] = (
        200,
        {"code": "ok", "details": {"id": "custom-app", "operation_id": "op-build"}},
    )
    result = harness.call(
        "create_vm_sandbox_template",
        name="custom-app",
        image="ubuntu:24.04",
        region=REGION,
        confirm=True,
        description="build",
    )
    assert result.data["details"]["operation_id"] == "op-build"
    assert _json(harness.requests[-1]) == {
        "name": "custom-app",
        "image": "ubuntu:24.04",
        "description": "build",
    }


def test_template_build_blocks_the_tenth_custom_template_and_two_builds(harness):
    custom = [
        {"id": f"app-{index}", "custom": True, "default_template": False, "status": "READY"}
        for index in range(10)
    ]
    harness.replies[("GET", f"{PREFIX}/templates")] = (200, _templates(custom))
    with pytest.raises(ToolError, match="10 custom templates"):
        harness.call(
            "create_vm_sandbox_template",
            name="custom-app",
            image="ubuntu:24.04",
            region=REGION,
            confirm=True,
        )
    building = [
        {"id": "build-a", "custom": True, "status": "BUILDING"},
        {"id": "build-b", "custom": True, "status": "pending"},
    ]
    harness.replies[("GET", f"{PREFIX}/templates")] = (200, _templates(building))
    with pytest.raises(ToolError, match="2 concurrent"):
        harness.call(
            "create_vm_sandbox_template",
            name="custom-app",
            image="ubuntu:24.04",
            region=REGION,
            confirm=True,
        )
    assert all(request.method == "GET" for request in harness.requests)


def test_platform_templates_cannot_be_deleted(harness):
    harness.replies[("GET", f"{PREFIX}/templates/base")] = (
        200,
        {"code": "ok", "details": {"id": "base", "default_template": True, "custom": False}},
    )
    with pytest.raises(ToolError, match="platform"):
        harness.call(
            "delete_vm_sandbox_template",
            template_id="base",
            region=REGION,
            confirm=True,
        )
    assert [request.method for request in harness.requests] == ["GET"]


def test_custom_template_delete_uses_template_id(harness):
    harness.replies[("GET", f"{PREFIX}/templates/custom-app")] = (
        200,
        {"code": "ok", "details": {"id": "custom-app", "default_template": False, "custom": True}},
    )
    harness.replies[("DELETE", f"{PREFIX}/templates/custom-app")] = (
        200,
        {"code": "ok", "details": {"id": "custom-app", "status": "deleted"}},
    )
    result = harness.call(
        "delete_vm_sandbox_template",
        template_id="custom-app",
        region=REGION,
        confirm=True,
    )
    assert result.data["details"]["status"] == "deleted"
    assert harness.requests[-1].method == "DELETE"


def test_wait_polls_until_success_and_timeout_does_not_cancel(harness, monkeypatch):
    clock = {"now": 0.0}

    def monotonic():
        return clock["now"]

    def sleep(seconds):
        clock["now"] += seconds

    monkeypatch.setattr(adapter.time, "monotonic", monotonic)
    monkeypatch.setattr(adapter.time, "sleep", sleep)
    harness.replies[("GET", f"{PREFIX}/operations/op-1")] = [
        (200, {"code": "ok", "details": {"id": "op-1", "state": "pending"}}),
        (200, {"code": "ok", "details": {"id": "op-1", "state": "running"}}),
        (200, {"code": "ok", "details": {"id": "op-1", "state": "succeeded"}}),
    ]
    result = harness.call(
        "wait_vm_sandbox_operation",
        operation_id="op-1",
        region=REGION,
        timeout_seconds=30,
        poll_interval_seconds=2,
    )
    assert result.data["details"]["state"] == "succeeded"
    assert len(harness.requests) == 3
    assert clock["now"] == 4

    clock["now"] = 0
    harness.requests.clear()
    harness.replies[("GET", f"{PREFIX}/operations/op-1")] = (
        200,
        {"code": "ok", "details": {"id": "op-1", "state": "pending"}},
    )
    with pytest.raises(ToolError, match="not cancelled"):
        harness.call(
            "wait_vm_sandbox_operation",
            operation_id="op-1",
            region=REGION,
            timeout_seconds=1,
            poll_interval_seconds=0.5,
        )


def test_failed_operation_is_an_error_and_hides_token_text(harness, monkeypatch):
    monkeypatch.setattr(adapter.time, "sleep", lambda seconds: None)
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.signature"
    harness.replies[("GET", f"{PREFIX}/operations/op-1")] = (
        200,
        {"code": "ok", "details": {"id": "op-1", "state": "failed", "error": f"boom {token}"}},
    )
    with pytest.raises(ToolError) as error:
        harness.call("wait_vm_sandbox_operation", operation_id="op-1", region=REGION)
    assert token not in str(error.value)
    assert "failed" in str(error.value)


def test_network_update_replaces_the_egress_policy(harness):
    harness.replies[("GET", f"{PREFIX}/sandboxes/{KRN}/network")] = (
        200,
        {"code": "ok", "details": {"egress": {"default_action": "allow"}}},
    )
    harness.replies[("PUT", f"{PREFIX}/sandboxes/{KRN}/network")] = (
        200,
        {
            "code": "ok",
            "details": {
                "egress": {"default_action": "allow", "deny": ["example.com"]},
                "operation_id": "op-net",
            },
        },
    )
    harness.call("get_vm_sandbox_network", krn_id=KRN, region=REGION)
    harness.call(
        "update_vm_sandbox_network",
        krn_id=KRN,
        region=REGION,
        confirm=True,
        network={"egress": {"default_action": "allow", "deny": ["example.com"]}},
    )
    assert harness.requests[-1].method == "PUT"
    assert _json(harness.requests[-1]) == {
        "egress": {"default_action": "allow", "deny": ["example.com"]}
    }


def test_exec_treats_nonzero_exit_as_failure_and_redacts_env(harness):
    harness.replies[("POST", f"{PREFIX}/sandboxes/{KRN}/exec")] = (
        200,
        {
            "code": "ok",
            "details": {
                "stdout": "saw secret-value",
                "stderr": "",
                "exit_code": 2,
                "duration_ms": 4,
                "timed_out": False,
            },
        },
    )
    with pytest.raises(ToolError, match="exit_code 2") as error:
        harness.call(
            "exec_vm_sandbox",
            krn_id=KRN,
            region=REGION,
            cmd="echo hi",
            confirm=True,
            env={"TOKEN": "secret-value"},
            cwd="/tmp/work",
            user="sandbox",
            timeout_seconds=30,
        )
    assert "secret-value" not in str(error.value)
    assert _json(harness.requests[0]) == {
        "cmd": "echo hi",
        "cwd": "/tmp/work",
        "env": {"TOKEN": "secret-value"},
        "user": "sandbox",
        "timeout_seconds": 30,
    }


def test_exec_returns_output_when_the_command_exits_zero(harness):
    harness.replies[("POST", f"{PREFIX}/sandboxes/{KRN}/exec")] = (
        200,
        {
            "code": "ok",
            "details": {
                "stdout": "ok",
                "stderr": "",
                "exit_code": 0,
                "duration_ms": 1,
                "timed_out": False,
            },
        },
    )
    result = harness.call(
        "exec_vm_sandbox",
        krn_id=KRN,
        region=REGION,
        cmd="true",
        confirm=True,
    )
    assert result.data["details"]["stdout"] == "ok"
    assert result.data["details"]["exit_code"] == 0


def test_async_commands_support_log_offsets_and_kill(harness):
    command = f"{PREFIX}/sandboxes/{KRN}/commands"
    harness.replies[("POST", command)] = (
        200,
        {"code": "ok", "details": {"command_id": "cmd-1", "status": "running"}},
    )
    harness.replies[("GET", command)] = (
        200,
        {"code": "ok", "details": {"commands": [], "krn_id": KRN}},
    )
    harness.replies[("GET", f"{command}/cmd-1")] = (
        200,
        {
            "code": "ok",
            "details": {
                "command": {"command_id": "cmd-1", "status": "running"},
                "stdout": "partial",
                "stderr": "",
                "stdout_offset": 4,
                "stderr_offset": 0,
            },
        },
    )
    harness.replies[("POST", f"{command}/cmd-1/kill")] = (
        200,
        {"code": "ok", "details": {"command_id": "cmd-1", "status": "killed"}},
    )
    harness.call(
        "create_vm_sandbox_command",
        krn_id=KRN,
        region=REGION,
        cmd="sleep 30",
        confirm=True,
        env={"JOB": "1"},
    )
    with pytest.raises(ToolError, match="reserved prefix"):
        harness.call(
            "create_vm_sandbox_command",
            krn_id=KRN,
            region=REGION,
            cmd="sleep 30",
            confirm=True,
            env={"KRUTRIM_TOKEN": "nope"},
        )
    harness.call("list_vm_sandbox_commands", krn_id=KRN, region=REGION)
    harness.call(
        "get_vm_sandbox_command",
        krn_id=KRN,
        command_id="cmd-1",
        region=REGION,
        stdout_offset=4,
        stderr_offset=0,
        max_bytes=128,
    )
    harness.call(
        "kill_vm_sandbox_command",
        krn_id=KRN,
        command_id="cmd-1",
        region=REGION,
        confirm=True,
    )
    assert dict(harness.requests[-2].url.params) == {
        "stdout_offset": "4",
        "stderr_offset": "0",
        "max_bytes": "128",
    }
    assert harness.requests[-1].url.path.endswith("/commands/cmd-1/kill")


def test_exec_allows_the_prefixes_the_exec_api_does_not_reserve(harness):
    harness.replies[("POST", f"{PREFIX}/sandboxes/{KRN}/exec")] = (
        200,
        {
            "code": "ok",
            "details": {"stdout": "", "stderr": "", "exit_code": 0, "duration_ms": 1},
        },
    )
    harness.call(
        "exec_vm_sandbox",
        krn_id=KRN,
        region=REGION,
        cmd="true",
        confirm=True,
        env={"KRUTRIM_DEBUG": "1"},
    )
    assert _json(harness.requests[0])["env"] == {"KRUTRIM_DEBUG": "1"}


def test_ports_accept_token_or_private_and_keep_the_credential_url(harness):
    ticket_url = "https://sandbox.example/ports/1?token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.signature"
    harness.replies[("POST", f"{PREFIX}/sandboxes/{KRN}/ports")] = (
        200,
        {
            "code": "ok",
            "details": {
                "port": 8080,
                "access": "token",
                "url": ticket_url,
                "created_at": 1,
            },
        },
    )
    harness.replies[("GET", f"{PREFIX}/sandboxes/{KRN}/ports")] = (
        200,
        {"code": "ok", "details": {"ports": [{"port": 8080, "access": "token"}]}},
    )
    harness.replies[("DELETE", f"{PREFIX}/sandboxes/{KRN}/ports/8080")] = (
        200,
        {"code": "ok", "details": {"krn_id": KRN, "port": 8080, "status": "closed"}},
    )
    exposed = harness.call(
        "expose_vm_sandbox_port",
        krn_id=KRN,
        region=REGION,
        port=8080,
        access="token",
        confirm=True,
    )
    assert exposed.data["details"]["url"] == ticket_url
    assert _json(harness.requests[0]) == {"port": 8080, "access": "token"}
    harness.call("list_vm_sandbox_ports", krn_id=KRN, region=REGION)
    closed = harness.call(
        "close_vm_sandbox_port",
        krn_id=KRN,
        region=REGION,
        port=8080,
        confirm=True,
    )
    assert closed.data["details"]["status"] == "closed"


def test_files_round_trip_text_and_withhold_binary(harness):
    harness.replies[("PUT", f"{PREFIX}/sandboxes/{KRN}/files")] = (
        200,
        {
            "code": "ok",
            "details": {
                "path": "/tmp/hello.txt",
                "size_bytes": 5,
                "sha256": "abc",
                "echo": "secret-file",
            },
        },
    )
    written = harness.call(
        "write_vm_sandbox_file",
        krn_id=KRN,
        region=REGION,
        path="/tmp/hello.txt",
        content="secret-file",
        confirm=True,
    )
    assert "secret-file" not in written.model_dump_json()
    upload = harness.requests[0]
    assert upload.content == b"secret-file"
    assert upload.headers["content-type"].startswith("application/octet-stream")
    assert dict(upload.url.params) == {"path": "/tmp/hello.txt"}
    assert "idempotency-key" not in {key.lower() for key in upload.headers}

    harness.replies[("GET", f"{PREFIX}/sandboxes/{KRN}/files")] = httpx.Response(
        200,
        content=b"hello",
    )
    read = harness.call(
        "read_vm_sandbox_file",
        krn_id=KRN,
        region=REGION,
        path="/tmp/hello.txt",
    )
    assert read.data == {"path": "/tmp/hello.txt", "content": "hello", "size_bytes": 5}

    harness.replies[("GET", f"{PREFIX}/sandboxes/{KRN}/files")] = httpx.Response(
        200,
        content=b"hidden-bytes\x00",
    )
    with pytest.raises(ToolError, match="binary") as error:
        harness.call(
            "read_vm_sandbox_file",
            krn_id=KRN,
            region=REGION,
            path="/tmp/hello.txt",
        )
    assert "hidden-bytes" not in str(error.value)


def test_terminal_ticket_is_returned_once_and_is_not_retried(harness):
    ticket = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.signature"
    harness.replies[("POST", f"{PREFIX}/sandboxes/{KRN}/terminal/ticket")] = (
        200,
        {
            "code": "ok",
            "details": {
                "krn_id": KRN,
                "ticket": ticket,
                "url": "wss://sandbox.example/terminal",
                "expires_at": "2026-11-12T00:01:00Z",
            },
        },
    )
    result = harness.call(
        "create_vm_sandbox_terminal_ticket",
        krn_id=KRN,
        region=REGION,
        confirm=True,
    )
    assert result.data["details"]["ticket"] == ticket
    assert result.data["details"]["url"] == "wss://sandbox.example/terminal"
    request = harness.requests[0]
    assert "idempotency-key" not in {key.lower() for key in request.headers}
    assert _json(request) == {}


def test_transport_errors_are_not_retried(harness):
    harness.replies[("GET", f"{PREFIX}/sandboxes")] = httpx.ConnectError("down")
    with pytest.raises(ToolError):
        harness.call("list_vm_sandboxes", region=REGION)
    assert len(harness.requests) == 1


def test_server_error_bodies_are_withheld(harness):
    harness.replies[("GET", f"{PREFIX}/sandboxes/{KRN}")] = httpx.Response(
        500,
        json={"message": "secret-backend-detail"},
    )
    with pytest.raises(ToolError) as error:
        harness.call("describe_vm_sandbox", krn_id=KRN, region=REGION)
    assert "secret-backend-detail" not in str(error.value)
    assert "withheld" in str(error.value)
