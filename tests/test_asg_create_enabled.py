"""create_asg / create_launch_template are part of the live catalog."""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.server import Settings as FastMCPSettings

from krutrim_mcp_server.compat import patch_client_compatibility
from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.profiles import ADDITIVE_TOOLS, UNAVAILABLE_TOOLS
from krutrim_mcp_server.server import create_server

REGION = "In-Bangalore-1"
VPC = "krn:vpc:In-Bangalore-1:7655600597:cust-uuid-1234:vpc:vpc-uuid-5678"
COMMON = dict(
    vpc_name="vpc_bng",
    vpc_krn=VPC,
    subnet_id="legacy-subnet-id",
    image_krn="krn:image:In-Bangalore-1:7655600597:cust:image:img-1",
    instance_name="web",
    instance_type="c1.small",
    min_count=1,
    max_count=3,
    policy=[{"metric": "cpu", "threshold": 70}],
    security_groups=["sg-1"],
    sshkey_name="key-1",
    volume_name="root",
    volume_size=[{"count": 1, "volume_size": 20}],
    volume_type="HNSS",
    region=REGION,
)


def _settings() -> Settings:
    return Settings(
        api_key="test-api-key-for-offline-tests",
        base_url="https://cloud.olakrutrim.com",
        default_region=REGION,
        read_only=False,
        log_level="WARNING",
        client_max_retries=0,
        tool_profile="admin",
        enable_sensitive_tools=True,
    )


def test_asg_create_tools_are_enabled_and_additive():
    assert UNAVAILABLE_TOOLS == set()
    assert {"create_asg", "create_launch_template"} <= ADDITIVE_TOOLS
    names = {tool.name for tool in create_server(_settings())._tool_manager.list_tools()}
    assert {"create_asg", "create_launch_template"} <= names


@pytest.fixture
def wire(monkeypatch):
    module = importlib.import_module("krutrim_mcp_server.tools.compute.auto_scaling")
    state = SimpleNamespace(requests=[], read_only=False, vpc_detail=None)
    state.vpc_detail = {"vpc_bng": {"networks": {"krn_id": "krn:net:In-Bangalore-1:1:2:net:3"}}}

    def handler(request: httpx.Request) -> httpx.Response:
        state.requests.append(request)
        if request.url.path.endswith("/v1/highlvlvpc/describe_vpc"):
            return httpx.Response(200, json=state.vpc_detail)
        return httpx.Response(200, json={"message": "accepted", "task_id": "t-1"})

    client = KrutrimClient(
        api_key="mcp-token-not-for-custom-headers",
        base_url="https://cloud.example.test",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    patch_client_compatibility(client)  # same step the production session performs
    session = SimpleNamespace(get_client=lambda: client)
    monkeypatch.setattr(module, "get_session", lambda: session)
    monkeypatch.setattr(module, "settings", lambda: state)
    FastMCPSettings.model_rebuild()
    server = FastMCP("asg-test")
    module.register(server)
    state.call = lambda _tool, **kwargs: server._tool_manager.get_tool(_tool).fn(**kwargs)
    yield state
    client.close()


def test_create_asg_wire(wire):
    result = wire.call("create_asg", asg_name="web-asg", confirm=True, **COMMON)
    assert result.ok is True
    lookup, request = wire.requests
    assert lookup.method == "GET"
    assert lookup.url.path.endswith("/v1/highlvlvpc/describe_vpc")
    assert lookup.url.params["vpc_name"] == "vpc_bng"
    assert lookup.headers["x-region"] == REGION
    assert request.method == "POST"
    assert request.url.path.endswith("/asg/v1")
    assert request.headers["x-region"] == REGION
    body = json.loads(request.content)
    assert body["asg_name"] == "web-asg"
    assert body["min"] == 1 and body["max"] == 3
    assert body["network_krn"] == "krn:net:In-Bangalore-1:1:2:net:3"


def test_create_launch_template_wire(wire):
    result = wire.call("create_launch_template", template_name="web-tpl", confirm=True, **COMMON)
    assert result.ok is True
    lookup, request = wire.requests
    assert lookup.url.path.endswith("/v1/highlvlvpc/describe_vpc")
    assert request.method == "POST"
    assert request.url.path.endswith("/asg/v1/create-launch-template")
    body = json.loads(request.content)
    assert body["template_name"] == "web-tpl"
    assert body["network_krn"] == "krn:net:In-Bangalore-1:1:2:net:3"


@pytest.mark.parametrize(
    "detail",
    [{}, {"vpc_bng": {}}, {"vpc_bng": {"networks": {}}}, ["not", "a", "mapping"]],
)
def test_create_asg_fails_clearly_when_vpc_has_no_network(wire, detail):
    wire.vpc_detail = detail
    with pytest.raises(ToolError, match="network"):
        wire.call("create_asg", asg_name="web-asg", confirm=True, **COMMON)
    assert [r.method for r in wire.requests] == ["GET"]  # never reached the create POST


@pytest.mark.parametrize(
    ("tool", "name_arg"),
    [("create_asg", "asg_name"), ("create_launch_template", "template_name")],
)
def test_create_tools_are_guarded(wire, tool, name_arg):
    kwargs = {name_arg: "x", **COMMON}
    with pytest.raises(ToolError, match="confirm=true"):
        wire.call(tool, confirm=False, **kwargs)
    wire.read_only = True
    with pytest.raises(ToolError, match="KRUTRIM_MCP_READ_ONLY"):
        wire.call(tool, confirm=True, **kwargs)
    assert wire.requests == []
