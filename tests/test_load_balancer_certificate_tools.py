"""Wire-level tests for the load balancer (lb) and certificate (kcm) tool groups."""

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

REGION = "In-Bangalore-1"
VPC = "krn:vpc:In-Bangalore-1:7655600597:cust-uuid-1234:vpc:vpc-uuid-5678"
MASKED_VPC = "krn:vpc:In-Bangalore-1:7655600597:***:vpc:vpc-uuid-5678"
LB = "krn:lb:In-Bangalore-1:7655600597:cust-uuid-1234:loadbalancer:lb-uuid-9999"
MASKED_LB = "krn:lb:In-Bangalore-1:7655600597:***:loadbalancer:lb-uuid-9999"
CERT = "cert-0001"


@pytest.fixture
def wire(monkeypatch):
    modules = [
        importlib.import_module("krutrim_mcp_server.tools.networking.load_balancers"),
        importlib.import_module("krutrim_mcp_server.tools.networking.certificates"),
    ]
    state = SimpleNamespace(requests=[], status=200, body={"ok": True}, read_only=False)

    def handler(request: httpx.Request) -> httpx.Response:
        state.requests.append(request)
        return httpx.Response(state.status, json=state.body)

    client = KrutrimClient(
        api_key="mcp-token-not-for-custom-headers",
        base_url="https://cloud.example.test",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    session = SimpleNamespace(get_client=lambda: client)
    FastMCPSettings.model_rebuild()
    server = FastMCP("lb-kcm-test")
    for module in modules:
        monkeypatch.setattr(module, "get_session", lambda: session)
        monkeypatch.setattr(module, "settings", lambda: state)
        module.register(server)
    state.call = lambda _tool, **kwargs: server._tool_manager.get_tool(_tool).fn(**kwargs)
    state.tool_names = lambda: {tool.name for tool in server._tool_manager.list_tools()}
    yield state
    client.close()


def _last(wire) -> httpx.Request:
    assert len(wire.requests) == 1, [str(r.url) for r in wire.requests]
    return wire.requests[0]


def _json(request: httpx.Request):
    return json.loads(request.content)


def test_registers_expected_tools(wire):
    assert wire.tool_names() == {
        "list_load_balancers",
        "describe_load_balancer",
        "get_load_balancer_payload",
        "get_load_balancer_task_status",
        "list_target_groups",
        "list_target_group_names",
        "get_detailed_target_groups",
        "create_load_balancer",
        "update_load_balancer",
        "delete_load_balancer",
        "create_target_group",
        "update_target_group",
        "delete_target_group",
        "list_certificates",
        "describe_certificate",
        "get_expiring_certificates",
        "import_certificate",
        "update_certificate",
        "delete_certificate",
        "add_certificate_tags",
        "get_certificate_tag_value",
    }


# ---------------------------------------------------------------- LB reads


def test_list_load_balancers_wire(wire):
    result = wire.call("list_load_balancers", vpc_id=VPC, region=REGION)
    request = _last(wire)
    assert result.ok is True
    assert request.method == "GET"
    assert request.url.path.endswith(f"/v3/highlvl/get_lb_list_new/{VPC}")
    assert request.headers["x-region"] == REGION


def test_describe_load_balancer_wire(wire):
    wire.call("describe_load_balancer", lb_krn=LB, region=REGION)
    request = _last(wire)
    assert request.method == "GET"
    assert request.url.path.endswith(f"/v3/highlvl/lb_details_new/{LB}")
    assert request.headers["x-region"] == REGION


def test_get_load_balancer_payload_wire(wire):
    wire.call("get_load_balancer_payload", lb_krn=LB, region=REGION)
    request = _last(wire)
    assert request.method == "GET"
    assert request.url.path.endswith(f"/v3/highlvl/fetch_payload_multiple/{LB}")


def test_get_load_balancer_task_status_wire(wire):
    wire.call("get_load_balancer_task_status", task_id="task-1", region=REGION)
    request = _last(wire)
    assert request.url.path.endswith("/v3/highlvl/task_status/task-1")
    assert request.headers["x-region"] == REGION


def test_list_target_groups_wire(wire):
    wire.call("list_target_groups", vpc_id=VPC, region=REGION)
    request = _last(wire)
    assert request.method == "GET"
    assert request.url.path.endswith("/v1/highlvl/get_tg_list")
    assert request.url.params["vpc_id"] == VPC


def test_list_target_group_names_wire(wire):
    wire.call("list_target_group_names", vpc_id=VPC, region=REGION)
    request = _last(wire)
    assert request.url.path.endswith("/v1/highlvl/get_target_group_names")
    assert request.url.params["vpc_id"] == VPC


def test_get_detailed_target_groups_derives_identity_headers(wire):
    wire.call(
        "get_detailed_target_groups",
        vpc_id=VPC,
        region=REGION,
        target_group_name="web-tg",
    )
    request = _last(wire)
    assert request.url.path.endswith("/v1/highlvl/get_target_groups")
    assert request.url.params["vpc_id"] == VPC
    assert request.url.params["target_group_name"] == "web-tg"
    assert request.headers["k-customer-id"] == "cust-uuid-1234"
    assert request.headers["x-account-id"] == "7655600597"
    assert request.headers["x-region"] == REGION


def test_get_detailed_target_groups_omits_name_when_not_given(wire):
    wire.call("get_detailed_target_groups", vpc_id=VPC, region=REGION)
    assert "target_group_name" not in _last(wire).url.params


# ------------------------------------------------------------- LB mutations


def test_create_load_balancer_wire(wire):
    data = {"name": "web-lb", "vpc_id": VPC}
    listeners = [{"protocol": "HTTP", "port": 80}]
    result = wire.call(
        "create_load_balancer",
        vpc_id=VPC,
        region=REGION,
        loadbalancer_data=data,
        listeners=listeners,
        confirm=True,
    )
    request = _last(wire)
    assert result.ok is True
    assert request.method == "POST"
    assert request.url.path.endswith("/v3/highlvl/create_load_balancer_orchestration")
    assert request.headers["k-customer-id"] == "cust-uuid-1234"
    assert request.headers["x-account-id"] == "7655600597"
    assert request.headers["x-region"] == REGION
    assert _json(request) == {"listeners": listeners, "loadbalancer_data": data}


def test_create_load_balancer_omits_unset_listeners(wire):
    wire.call(
        "create_load_balancer",
        vpc_id=VPC,
        region=REGION,
        loadbalancer_data={"name": "web-lb"},
        confirm=True,
    )
    assert _json(_last(wire)) == {"loadbalancer_data": {"name": "web-lb"}}


def test_create_target_group_omits_unset_optionals(wire):
    wire.call(
        "create_target_group",
        vpc_id=VPC,
        region=REGION,
        target_group_name="web-tg",
        confirm=True,
    )
    assert _json(_last(wire)) == {"target_group_name": "web-tg", "vpc_id": VPC}


def test_update_load_balancer_wire_derives_identity_from_lb_krn(wire):
    wire.call(
        "update_load_balancer",
        lb_krn=LB,
        region=REGION,
        listeners=[{"protocol": "HTTPS", "port": 443}],
        security_groups=["sg-1"],
        confirm=True,
    )
    request = _last(wire)
    assert request.method == "PUT"
    assert request.url.path.endswith(f"/v3/highlvl/update_load_balancer/{LB}")
    assert request.headers["k-customer-id"] == "cust-uuid-1234"
    assert request.headers["x-account-id"] == "7655600597"
    body = _json(request)
    assert body["lb_krn"] == LB
    assert body["listeners"] == [{"protocol": "HTTPS", "port": 443}]
    assert body["security_groups"] == ["sg-1"]
    assert "loadbalancer_data" not in body


def test_update_load_balancer_requires_a_change(wire):
    with pytest.raises(ToolError, match="at least one"):
        wire.call("update_load_balancer", lb_krn=LB, region=REGION, confirm=True)
    assert wire.requests == []


def test_delete_load_balancer_wire(wire):
    wire.call("delete_load_balancer", lb_krn=LB, region=REGION, confirm=True)
    request = _last(wire)
    assert request.method == "DELETE"
    assert request.url.path.endswith(f"/v3/highlvl/loadbalancer/{LB}")
    assert request.headers["x-region"] == REGION


def test_create_target_group_wire(wire):
    wire.call(
        "create_target_group",
        vpc_id=VPC,
        region=REGION,
        target_group_name="web-tg",
        health_monitor={"delay": 5, "h_type": "HTTP", "timeout": 3, "url_path": "/"},
        members=[{"address": "10.0.0.5", "name": "vm-1", "protocol_port": 80, "weight": 1}],
        confirm=True,
    )
    request = _last(wire)
    assert request.method == "POST"
    assert request.url.path.endswith("/v1/highlvl/create_target_group")
    assert request.headers["x-region"] == REGION
    body = _json(request)
    assert body["vpc_id"] == VPC
    assert body["target_group_name"] == "web-tg"
    assert body["health_monitor"]["h_type"] == "HTTP"
    assert body["members"][0]["address"] == "10.0.0.5"


def test_update_target_group_wire(wire):
    wire.call(
        "update_target_group",
        vpc_id=VPC,
        region=REGION,
        target_group_name="web-tg",
        members=[{"address": "10.0.0.6", "name": "vm-2", "protocol_port": 80, "weight": 2}],
        confirm=True,
    )
    request = _last(wire)
    assert request.method == "PUT"
    assert request.url.path.endswith("/v1/highlvl/updatetg")
    assert request.headers["k-customer-id"] == "cust-uuid-1234"
    assert request.headers["x-account-id"] == "7655600597"
    body = _json(request)
    assert body["target_group_name"] == "web-tg"
    assert body["members"][0]["weight"] == 2
    assert "health_monitor" not in body


def test_delete_target_group_wire(wire):
    wire.call(
        "delete_target_group",
        vpc_id=VPC,
        region=REGION,
        target_group_name="web-tg",
        confirm=True,
    )
    request = _last(wire)
    assert request.method == "DELETE"
    assert request.url.path.endswith("/v1/highlvl/target_group")
    assert request.url.params["target_group_name"] == "web-tg"
    assert request.url.params["vpc_id"] == VPC


# ------------------------------------------------------------- LB guardrails

LB_MUTATIONS = [
    ("create_load_balancer", dict(vpc_id=VPC, loadbalancer_data={"name": "x"})),
    ("update_load_balancer", dict(lb_krn=LB, security_groups=["sg"])),
    ("delete_load_balancer", dict(lb_krn=LB)),
    ("create_target_group", dict(vpc_id=VPC, target_group_name="t")),
    ("update_target_group", dict(vpc_id=VPC, target_group_name="t", members=[])),
    ("delete_target_group", dict(vpc_id=VPC, target_group_name="t")),
]


@pytest.mark.parametrize(("name", "kwargs"), LB_MUTATIONS)
def test_lb_mutations_require_confirm(wire, name, kwargs):
    with pytest.raises(ToolError, match="confirm=true"):
        wire.call(name, region=REGION, confirm=False, **kwargs)
    assert wire.requests == []


@pytest.mark.parametrize(("name", "kwargs"), LB_MUTATIONS)
def test_lb_mutations_blocked_in_read_only_mode(wire, name, kwargs):
    wire.read_only = True
    with pytest.raises(ToolError, match="KRUTRIM_MCP_READ_ONLY"):
        wire.call(name, region=REGION, confirm=True, **kwargs)
    assert wire.requests == []


@pytest.mark.parametrize(
    ("name", "kwargs"),
    [
        ("list_load_balancers", dict(vpc_id=VPC)),
        ("describe_load_balancer", dict(lb_krn=LB)),
        ("get_load_balancer_payload", dict(lb_krn=LB)),
        ("get_load_balancer_task_status", dict(task_id="t")),
        ("list_target_groups", dict(vpc_id=VPC)),
        ("list_target_group_names", dict(vpc_id=VPC)),
        ("get_detailed_target_groups", dict(vpc_id=VPC)),
        ("create_load_balancer", dict(vpc_id=VPC, loadbalancer_data={}, confirm=True)),
        ("update_load_balancer", dict(lb_krn=LB, security_groups=[], confirm=True)),
        ("delete_load_balancer", dict(lb_krn=LB, confirm=True)),
        ("create_target_group", dict(vpc_id=VPC, target_group_name="t", confirm=True)),
        ("update_target_group", dict(vpc_id=VPC, target_group_name="t", confirm=True)),
        ("delete_target_group", dict(vpc_id=VPC, target_group_name="t", confirm=True)),
    ],
)
def test_lb_tools_reject_unknown_region(wire, name, kwargs):
    with pytest.raises(ToolError, match="unknown region"):
        wire.call(name, region="Mars-1", **kwargs)
    assert wire.requests == []


@pytest.mark.parametrize(
    ("name", "kwargs"),
    [
        ("get_detailed_target_groups", dict(vpc_id=MASKED_VPC)),
        ("create_load_balancer", dict(vpc_id=MASKED_VPC, loadbalancer_data={}, confirm=True)),
        ("update_load_balancer", dict(lb_krn=MASKED_LB, security_groups=["sg"], confirm=True)),
        (
            "update_target_group",
            dict(vpc_id=MASKED_VPC, target_group_name="t", members=[], confirm=True),
        ),
    ],
)
def test_identity_tools_reject_masked_krns_before_any_request(wire, name, kwargs):
    with pytest.raises(ToolError, match="masked"):
        wire.call(name, region=REGION, **kwargs)
    assert wire.requests == []


def test_identity_derivation_rejects_non_krn(wire):
    with pytest.raises(ToolError, match="full KRN"):
        wire.call("get_detailed_target_groups", vpc_id="not-a-krn", region=REGION)
    assert wire.requests == []


# ------------------------------------------------------------- certificates


def test_list_certificates_wire(wire):
    wire.call("list_certificates", vpc_id=VPC)
    request = _last(wire)
    assert request.method == "GET"
    assert request.url.path.endswith("/kcm/v1/certs")
    assert request.url.params["vpcId"] == VPC


def test_describe_certificate_wire(wire):
    wire.call("describe_certificate", cert_id=CERT)
    request = _last(wire)
    assert request.url.path.endswith("/kcm/v1/certs")
    assert request.url.params["certId"] == CERT


def test_get_expiring_certificates_wire(wire):
    wire.call("get_expiring_certificates", vpc_id=VPC, date="2027-01-31")
    request = _last(wire)
    assert request.url.path.endswith("/kcm/v1/certs/expiringIn")
    assert request.url.params["date"] == "2027-01-31"
    assert request.url.params["vpcId"] == VPC


def test_get_expiring_certificates_rejects_bad_date(wire):
    with pytest.raises(ToolError, match="YYYY-MM-DD"):
        wire.call("get_expiring_certificates", vpc_id=VPC, date="31/01/2027")
    assert wire.requests == []


def test_import_certificate_wire_multipart(wire, tmp_path):
    pem = tmp_path / "site.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n")
    wire.call(
        "import_certificate",
        vpc_id=VPC,
        cert_file_path=str(pem),
        name="site-cert",
        tags='{"env":"prod"}',
        confirm=True,
    )
    request = _last(wire)
    assert request.method == "POST"
    assert request.url.path.endswith("/kcm/v1/certs/import")
    assert request.headers["x-vpc-id"] == VPC
    assert request.headers["content-type"].startswith("multipart/form-data; boundary=")
    body = request.content.decode()
    assert 'name="certFile"' in body
    assert "-----BEGIN CERTIFICATE-----" in body
    assert 'name="name"' in body and "site-cert" in body
    assert 'name="tags"' in body


@pytest.mark.parametrize(
    ("filename", "content", "match"),
    [
        ("missing.pem", None, "not found"),
        ("evil.sh", b"x", "extension"),
        ("big.pem", b"x" * (1024 * 1024 + 1), "too large"),
        ("empty.pem", b"", "empty"),
    ],
)
def test_import_certificate_rejects_bad_files(wire, tmp_path, filename, content, match):
    path = tmp_path / filename
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(ToolError, match=match):
        wire.call(
            "import_certificate", vpc_id=VPC, cert_file_path=str(path), confirm=True
        )
    assert wire.requests == []


def test_import_certificate_rejects_directory(wire, tmp_path):
    directory = tmp_path / "dir.pem"
    directory.mkdir()
    with pytest.raises(ToolError, match="regular file"):
        wire.call("import_certificate", vpc_id=VPC, cert_file_path=str(directory), confirm=True)
    assert wire.requests == []


def test_update_certificate_wire_multipart(wire, tmp_path):
    pem = tmp_path / "renewed.crt"
    pem.write_text("PEMDATA")
    wire.call(
        "update_certificate",
        cert_id=CERT,
        vpc_id=VPC,
        cert_file_path=str(pem),
        flag="renew",
        confirm=True,
    )
    request = _last(wire)
    assert request.method == "PUT"
    assert request.url.path.endswith(f"/kcm/v1/certs/{CERT}")
    assert request.headers["x-vpc-id"] == VPC
    assert request.headers["content-type"].startswith("multipart/form-data; boundary=")
    body = request.content.decode()
    assert "PEMDATA" in body
    assert 'name="flag"' in body


def test_update_certificate_requires_a_change(wire):
    with pytest.raises(ToolError, match="at least one"):
        wire.call("update_certificate", cert_id=CERT, vpc_id=VPC, confirm=True)
    assert wire.requests == []


def test_get_certificate_tag_value_wire(wire):
    wire.call("get_certificate_tag_value", cert_id=CERT, tag_name="env")
    request = _last(wire)
    assert request.method == "GET"
    assert request.url.path.endswith("/kcm/v1/certs/tags")
    assert request.url.params["certId"] == CERT
    assert request.url.params["tagName"] == "env"


def test_delete_certificate_wire(wire):
    wire.call("delete_certificate", cert_id=CERT, confirm=True)
    request = _last(wire)
    assert request.method == "DELETE"
    assert request.url.path.endswith(f"/kcm/v1/certs/{CERT}")


def test_add_certificate_tags_wire(wire):
    wire.call("add_certificate_tags", cert_id=CERT, tags={"env": "prod"}, confirm=True)
    request = _last(wire)
    assert request.method == "POST"
    assert request.url.path.endswith(f"/kcm/v1/certs/tags/{CERT}")
    assert _json(request) == {"env": "prod"}


CERT_MUTATIONS = [
    ("import_certificate", dict(vpc_id=VPC, cert_file_path="/nonexistent/a.pem")),
    ("update_certificate", dict(cert_id=CERT, vpc_id=VPC, flag="x")),
    ("delete_certificate", dict(cert_id=CERT)),
    ("add_certificate_tags", dict(cert_id=CERT, tags={"a": "b"})),
]


@pytest.mark.parametrize(("name", "kwargs"), CERT_MUTATIONS)
def test_cert_mutations_require_confirm(wire, name, kwargs):
    with pytest.raises(ToolError, match="confirm=true"):
        wire.call(name, confirm=False, **kwargs)
    assert wire.requests == []


@pytest.mark.parametrize(("name", "kwargs"), CERT_MUTATIONS)
def test_cert_mutations_blocked_in_read_only_mode(wire, name, kwargs):
    wire.read_only = True
    with pytest.raises(ToolError, match="KRUTRIM_MCP_READ_ONLY"):
        wire.call(name, confirm=True, **kwargs)
    assert wire.requests == []


@pytest.mark.parametrize(
    "kwargs",
    [dict(cert_id=" "), dict(cert_id="")],
)
def test_cert_ids_must_be_non_empty(wire, kwargs):
    with pytest.raises(ToolError, match="cert_id"):
        wire.call("describe_certificate", **kwargs)
    assert wire.requests == []
