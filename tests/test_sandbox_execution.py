"""Sandbox execution contract tests using the real SDK, never live cloud."""

import importlib
import json
from types import SimpleNamespace

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Settings as FastMCPSettings

SANDBOX_ID = "krn:sandbox:In-Bangalore-1:account:12345678-1234-1234-1234-123456789abc"


@pytest.fixture
def wire(monkeypatch):
    execution = importlib.import_module("krutrim_mcp_server.tools.sandbox.execution")
    state = SimpleNamespace(
        requests=[],
        response={"status": 200, "data": {}},
        status=200,
        error=None,
        reads=0,
        read_only=False,
        headers={},
        content=None,
    )

    def handler(request):
        state.requests.append(request)
        if state.error:
            raise state.error("private input must not be reflected", request=request)
        if state.content is not None:
            return httpx.Response(state.status, content=state.content, headers=state.headers)
        return httpx.Response(state.status, json=state.response, headers=state.headers)

    client = KrutrimClient(
        api_key="mcp-token-not-for-custom-headers",
        base_url="https://cloud.example.test",
        max_retries=2,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    def get_client():
        state.reads += 1
        return client

    monkeypatch.setattr(execution, "get_session", lambda: SimpleNamespace(get_client=get_client))
    monkeypatch.setattr(execution, "settings", lambda: state)
    state.http_client = client._client
    FastMCPSettings.model_rebuild()
    server = FastMCP("sandbox-test")
    execution.register(server)
    state.tool = lambda name: server._tool_manager.get_tool(name)
    state.call = lambda name, **kwargs: state.tool(name).fn(**kwargs)
    yield state
    client.close()


def test_command_literal_sdk_wire(wire):
    command = "  printf '%s' '$NOT_EXPANDED'\n"
    wire.response = {"status": 200, "data": {"stdout": "hello", "stderr": "", "exitCode": 0}}
    result = wire.call(
        "run_sandbox_command",
        sandbox_id=SANDBOX_ID,
        command=command,
        cwd="/workspace",
        envs={"MODE": "demo"},
        timeout_seconds=270,
        confirm=True,
    )
    assert result.ok is True
    assert result.data["data"]["stdout"] == "hello"
    assert result.data["data"]["exit_code"] == 0
    assert len(wire.requests) == 1
    request = wire.requests[0]
    assert request.method == "POST"
    assert request.url.path == f"/omni/sandbox/v1/sandbox/{SANDBOX_ID}/commands"
    assert json.loads(request.content) == {
        "cmd": command,
        "timeoutSeconds": 270,
        "cwd": "/workspace",
        "envs": {"MODE": "demo"},
    }
    assert request.extensions["timeout"]["read"] == 280


@pytest.mark.parametrize(
    "overrides",
    [
        {"confirm": False},
        {"confirm": "true"},
        {"confirm": 1},
        {"read_only": True},
        {"timeout_seconds": True},
        {"timeout_seconds": "60"},
        {"timeout_seconds": 0},
        {"timeout_seconds": 271},
        {"timeout_seconds": 1.5},
        {"command": ""},
        {"command": "x" * 100001},
        {"command": 123},
        {"envs": {"X": 123}},
        {"envs": {"BAD=NAME": "x"}},
        {"envs": {"X": "x" * 1048577}},
        {"cwd": "\u0000"},
        {"cwd": 123},
    ],
)
def test_command_rejected_before_client_access(wire, overrides):
    from mcp.server.fastmcp.exceptions import ToolError

    kwargs = dict(sandbox_id=SANDBOX_ID, command="cat /etc/hostname", confirm=True)
    overrides = dict(overrides)
    wire.read_only = overrides.pop("read_only", False)
    kwargs.update(overrides)
    with pytest.raises(ToolError):
        wire.call("run_sandbox_command", **kwargs)
    assert wire.reads == 0
    assert wire.requests == []


@pytest.mark.parametrize("port", [1024, 65535])
def test_close_port_sdk_wire(wire, port):
    wire.status = 204
    wire.content = b""
    assert wire.tool("close_sandbox_port") is not None
    result = wire.call("close_sandbox_port", sandbox_id=SANDBOX_ID, port=port, confirm=True)
    assert result.ok is True
    assert len(wire.requests) == 1
    assert wire.requests[0].method == "DELETE"
    assert wire.requests[0].url.path == f"/omni/sandbox/v1/sandbox/{SANDBOX_ID}/ports/{port}"


@pytest.mark.parametrize(
    "overrides",
    [
        {"confirm": False},
        {"confirm": "true"},
        {"confirm": 1},
        {"read_only": True},
        {"port": 1023},
        {"port": 65536},
        {"port": True},
        {"port": "8080"},
        {"port": 8080.0},
        {"sandbox_id": "a%2fb"},
    ],
)
def test_close_port_guards_before_client(wire, overrides):
    from mcp.server.fastmcp.exceptions import ToolError

    assert wire.tool("close_sandbox_port") is not None
    kwargs = dict(sandbox_id=SANDBOX_ID, port=8080, confirm=True)
    overrides = dict(overrides)
    wire.read_only = overrides.pop("read_only", False)
    kwargs.update(overrides)
    with pytest.raises(ToolError):
        wire.call("close_sandbox_port", **kwargs)
    assert wire.reads == 0


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def test_proxy_sdk_wire(wire, method):
    wire.response = {"answer": "hello"}
    assert wire.tool("sandbox_proxy_request") is not None
    result = wire.call(
        "sandbox_proxy_request",
        sandbox_id=SANDBOX_ID,
        method=method,
        path="/api/v1/health",
        json_body={"question": "literal"},
        confirm=True,
    )
    assert result.data == {"status_code": 200, "body": {"answer": "hello"}}
    assert len(wire.requests) == 1
    request = wire.requests[0]
    assert request.method == method
    assert request.url.host == "cloud.example.test"
    assert request.url.path == f"/omni/sandbox/v1/{SANDBOX_ID}/api/v1/health"
    assert json.loads(request.content) == {"question": "literal"}
    assert request.headers["authorization"] == "Bearer mcp-token-not-for-custom-headers"
    assert all(
        value != "mcp-token-not-for-custom-headers" for key, value in request.headers.items()
    )
    assert not any(key.startswith("x-krutrim") for key in request.headers)


@pytest.mark.parametrize(
    "overrides",
    [
        {"confirm": False},
        {"confirm": "true"},
        {"confirm": 1},
        {"read_only": True},
        {"method": "get"},
        {"method": "CONNECT"},
        {"method": "TRACE"},
        {"method": "POST\r\nX: bad"},
        {"timeout_seconds": True},
        {"timeout_seconds": 0},
        {"timeout_seconds": 271},
        {"json_body": {"x": 1}, "content": "text"},
        {"content": b"binary"},
        {"sandbox_id": "a/b"},
    ],
)
def test_proxy_guarded_even_get(wire, overrides):
    from mcp.server.fastmcp.exceptions import ToolError

    assert wire.tool("sandbox_proxy_request") is not None
    kwargs = dict(sandbox_id=SANDBOX_ID, method="GET", path="/health", confirm=True)
    overrides = dict(overrides)
    wire.read_only = overrides.pop("read_only", False)
    kwargs.update(overrides)
    with pytest.raises(ToolError):
        wire.call("sandbox_proxy_request", **kwargs)
    assert wire.reads == 0


@pytest.mark.parametrize(
    "path",
    [
        "",
        "health",
        "https://attacker.test/x",
        "//attacker.test/x",
        "/a//b",
        "/a/../b",
        "/a/./b",
        "/..",
        "/%2e%2e/x",
        "/%252e%252e/x",
        "/a%2fb",
        "/a%5cb",
        "/a\\b",
        "/a\nb",
        "/a?x=1",
        "/a#fragment",
        "/a\x00",
        "/a\u0085",
        "/http://evil",
    ],
)
def test_proxy_path_cannot_escape_sdk_target(wire, path):
    from mcp.server.fastmcp.exceptions import ToolError

    assert wire.tool("sandbox_proxy_request") is not None
    with pytest.raises(ToolError):
        wire.call(
            "sandbox_proxy_request", sandbox_id=SANDBOX_ID, method="GET", path=path, confirm=True
        )
    assert wire.reads == 0


MUTATIONS = [
    ("run_sandbox_command", {"command": "private-command", "envs": {"SECRET": "private-env"}}),
    ("open_sandbox_port", {"port": 8080, "allow_public_exposure": True}),
    ("close_sandbox_port", {"port": 8080}),
    ("sandbox_proxy_request", {"method": "GET", "path": "/health", "content": "private-body"}),
]


@pytest.mark.parametrize("name,kwargs", MUTATIONS)
@pytest.mark.parametrize("failure", ["timeout", "server", "validation"])
def test_sdk_failure_never_retried_or_reflected(wire, name, kwargs, failure):
    from mcp.server.fastmcp.exceptions import ToolError

    if failure == "timeout":
        wire.error = httpx.ReadTimeout
    else:
        wire.status = 500 if failure == "server" else 422
        wire.response = {"message": "private-command private-env private-body private-header"}
    with pytest.raises(ToolError) as exc:
        wire.call(name, sandbox_id=SANDBOX_ID, confirm=True, **kwargs)
    assert len(wire.requests) == 1
    assert "private-" not in str(exc.value)
    assert "not retried" in str(exc.value)


@pytest.mark.parametrize(
    "payload",
    [
        {"content": "x" * 1048577},
        {"content": "🙂" * 262145},
        {"json_body": {"blob": "x" * 1048577}},
        {"json_body": {"value": float("nan")}},
        {"json_body": {"x": b"private-body"}},
    ],
)
def test_proxy_request_limit_before_client(wire, payload):
    from mcp.server.fastmcp.exceptions import ToolError

    with pytest.raises(ToolError) as exc:
        wire.call(
            "sandbox_proxy_request",
            sandbox_id=SANDBOX_ID,
            method="POST",
            path="/",
            confirm=True,
            **payload,
        )
    assert wire.reads == 0
    assert "private-body" not in str(exc.value)


@pytest.mark.parametrize(
    "content_type,body",
    [
        ("text/plain", b"x" * 1048577),
        ("application/octet-stream", b"secret"),
        ("text/plain", b"\xffprivate-body"),
        ("text/plain", b"\x00private-body"),
    ],
    ids=["oversized", "binary-type", "invalid-utf8", "binary-control"],
)
def test_proxy_response_limits_and_binary_rejection(wire, content_type, body):
    from mcp.server.fastmcp.exceptions import ToolError

    wire.content = body
    wire.headers = {"content-type": content_type, "set-cookie": "private-header"}
    with pytest.raises(ToolError) as exc:
        wire.call(
            "sandbox_proxy_request", sandbox_id=SANDBOX_ID, method="GET", path="/", confirm=True
        )
    assert "private-" not in str(exc.value)
    assert len(wire.requests) == 1


@pytest.mark.parametrize(
    "body",
    [
        b'{"password":"private-body","nested":{"token":"private-token"},"note":"password=private-note"}',
        b"password=private-body\nAuthorization: Bearer private-token",
    ],
)
def test_proxy_response_redaction_and_no_headers(wire, body):
    wire.content = body
    wire.headers = {
        "content-type": "text/plain",
        "set-cookie": "session=private-cookie",
        "x-secret": "private-header",
    }
    result = wire.call(
        "sandbox_proxy_request", sandbox_id=SANDBOX_ID, method="GET", path="/", confirm=True
    )
    encoded = result.model_dump_json()
    assert "private-" not in encoded
    assert "headers" not in result.data
    assert "base64" not in encoded


@pytest.mark.parametrize("location", ["https://attacker.test/steal", "/iam/v1/users"])
def test_proxy_never_follows_redirect(wire, location):
    from mcp.server.fastmcp.exceptions import ToolError

    wire.http_client.follow_redirects = True
    wire.status = 307
    wire.headers = {"location": location}
    with pytest.raises(ToolError):
        wire.call(
            "sandbox_proxy_request",
            sandbox_id=SANDBOX_ID,
            method="POST",
            path="/",
            content="private-body",
            confirm=True,
        )
    assert len(wire.requests) == 1
    assert wire.http_client.follow_redirects is True
    assert not wire.http_client.is_closed


def test_proxy_text_request_content_type(wire):
    wire.call(
        "sandbox_proxy_request",
        sandbox_id=SANDBOX_ID,
        method="POST",
        path="/",
        content="  literal body\n",
        confirm=True,
    )
    assert wire.requests[0].content == b"  literal body\n"
    assert wire.requests[0].headers["content-type"].startswith("text/plain")


@pytest.mark.parametrize("name,kwargs", MUTATIONS)
@pytest.mark.parametrize("confirm", ["true", 1, 0, "false"])
def test_mcp_strict_confirmation(wire, name, kwargs, confirm):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        wire.tool(name).fn_metadata.arg_model.model_validate(
            dict(sandbox_id=SANDBOX_ID, confirm=confirm, **kwargs)
        )
    assert wire.reads == 0


def test_proxy_schema_has_no_target_or_header_overrides(wire):
    import asyncio

    tool = wire.tool("sandbox_proxy_request")
    assert not {"headers", "extra_headers", "base_url", "url", "query", "extra_query"} & set(
        tool.parameters["properties"]
    )
    assert set(tool.parameters["properties"]["method"]["enum"]) == {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    }
    # FastMCP currently ignores unknown JSON keys. They must never reach the SDK.
    asyncio.run(
        tool.run(
            dict(
                sandbox_id=SANDBOX_ID,
                method="GET",
                path="/",
                confirm=True,
                headers={
                    "Authorization": "attacker",
                    "Cookie": "private-cookie",
                    "Host": "attacker.test",
                    "x-krutrim-token": "private-token",
                },
                base_url="https://attacker.test",
            )
        )
    )
    request = wire.requests[0]
    assert request.url.host == "cloud.example.test"
    assert request.headers["authorization"] == "Bearer mcp-token-not-for-custom-headers"
    assert "cookie" not in request.headers
    assert "x-krutrim-token" not in request.headers


@pytest.mark.parametrize("name,kwargs", [MUTATIONS[0], MUTATIONS[1], ("list_sandbox_ports", {})])
def test_model_response_cannot_be_null(wire, name, kwargs):
    from mcp.server.fastmcp.exceptions import ToolError

    wire.content = b"null"
    wire.headers = {"content-type": "application/json"}
    if name != "list_sandbox_ports":
        kwargs = {**kwargs, "confirm": True}
    with pytest.raises(ToolError, match="withheld"):
        wire.call(name, sandbox_id=SANDBOX_ID, **kwargs)


def test_close_port_rejects_failed_application_envelope(wire):
    from mcp.server.fastmcp.exceptions import ToolError

    wire.response = {"status": 500, "message": "opaque-envelope-secret"}
    with pytest.raises(ToolError) as error:
        wire.call("close_sandbox_port", sandbox_id=SANDBOX_ID, port=8080, confirm=True)
    assert "opaque-envelope-secret" not in str(error.value)
    assert "withheld" in str(error.value)
    assert len(wire.requests) == 1


@pytest.mark.parametrize("name,kwargs", [MUTATIONS[0], MUTATIONS[1], ("list_sandbox_ports", {})])
def test_model_error_envelope_does_not_reflect_body(wire, name, kwargs):
    from mcp.server.fastmcp.exceptions import ToolError

    wire.response = {"status": 500, "message": "private-env", "data": {"detail": "private-env"}}
    if name != "list_sandbox_ports":
        kwargs = {**kwargs, "confirm": True}
    with pytest.raises(ToolError) as exc:
        wire.call(name, sandbox_id=SANDBOX_ID, **kwargs)
    assert "private-env" not in str(exc.value)


@pytest.mark.parametrize("reverse", [False, True], ids=["short-first", "long-first"])
def test_command_overlapping_environment_values_fully_redacted(wire, reverse):
    values = ["opaque-prefix", "opaque-prefix-private-suffix", ""]
    if reverse:
        values.reverse()
    wire.response = {
        "status": 200,
        "data": {
            "stdout": "opaque-prefix-private-suffix opaque-prefix",
            "stderr": "opaque-prefix-private-suffix",
            "extra": [{"echo": "opaque-prefix-private-suffix"}],
        },
    }
    result = wire.call(
        "run_sandbox_command",
        sandbox_id=SANDBOX_ID,
        command="env",
        envs={f"CUSTOM_{index}": value for index, value in enumerate(values)},
        confirm=True,
    )
    assert "opaque-prefix" not in result.model_dump_json()
    assert "private-suffix" not in result.model_dump_json()
    assert result.data["data"]["stdout"] == "***REDACTED*** ***REDACTED***"


def test_command_known_environment_values_redacted(wire):
    wire.response = {
        "status": 200,
        "data": {"stdout": "result opaque-env-value\n", "stderr": "opaque-env-value"},
    }
    result = wire.call(
        "run_sandbox_command",
        sandbox_id=SANDBOX_ID,
        command="env",
        envs={"CUSTOM": "opaque-env-value"},
        confirm=True,
    )
    assert "opaque-env-value" not in result.model_dump_json()


def test_command_response_redaction_and_limit(wire):
    from mcp.server.fastmcp.exceptions import ToolError

    wire.response = {
        "status": 200,
        "message": "private-env",
        "data": {"stdout": "password=private-env"},
    }
    result = wire.call("run_sandbox_command", sandbox_id=SANDBOX_ID, command="pwd", confirm=True)
    assert "private-env" not in result.model_dump_json()
    wire.response = {"data": {"stdout": "x" * 1048577}}
    with pytest.raises(ToolError, match="1 MiB"):
        wire.call("run_sandbox_command", sandbox_id=SANDBOX_ID, command="pwd", confirm=True)


def test_open_port_sdk_wire(wire):
    wire.response = {"status": 200, "data": {"port": 8080, "status": "active"}}
    assert wire.tool("open_sandbox_port") is not None
    result = wire.call(
        "open_sandbox_port",
        sandbox_id=SANDBOX_ID,
        port=8080,
        allow_public_exposure=True,
        confirm=True,
    )
    assert result.data["data"]["port"] == 8080
    assert len(wire.requests) == 1
    assert wire.requests[0].method == "POST"
    assert wire.requests[0].url.path == f"/omni/sandbox/v1/sandbox/{SANDBOX_ID}/ports"
    assert json.loads(wire.requests[0].content) == {"port": 8080}


@pytest.mark.parametrize(
    "overrides",
    [
        {"confirm": False},
        {"confirm": "true"},
        {"confirm": 1},
        {"read_only": True},
        {"allow_public_exposure": False},
        {"allow_public_exposure": "true"},
        {"allow_public_exposure": 1},
        {"port": 1023},
        {"port": 65536},
        {"port": True},
        {"port": "8080"},
        {"port": 8080.0},
        {"sandbox_id": "a/b"},
    ],
)
def test_open_port_guards_before_client(wire, overrides):
    from mcp.server.fastmcp.exceptions import ToolError

    assert wire.tool("open_sandbox_port") is not None
    kwargs = dict(sandbox_id=SANDBOX_ID, port=8080, confirm=True, allow_public_exposure=True)
    overrides = dict(overrides)
    wire.read_only = overrides.pop("read_only", False)
    kwargs.update(overrides)
    with pytest.raises(ToolError):
        wire.call("open_sandbox_port", **kwargs)
    assert wire.reads == 0


def test_list_ports_sdk_wire_read_only(wire):
    wire.read_only = True
    wire.response = {
        "status": 200,
        "data": [{"port": 8080, "status": "active", "url": "https://service.test"}],
    }
    assert wire.tool("list_sandbox_ports") is not None
    result = wire.call("list_sandbox_ports", sandbox_id=SANDBOX_ID)
    assert result.data["data"][0]["port"] == 8080
    assert "confirm" not in wire.tool("list_sandbox_ports").parameters["properties"]
    assert len(wire.requests) == 1
    assert wire.requests[0].method == "GET"
    assert wire.requests[0].url.path == f"/omni/sandbox/v1/sandbox/{SANDBOX_ID}/ports"


def test_list_ports_rejects_unsafe_identifier(wire):
    from mcp.server.fastmcp.exceptions import ToolError

    assert wire.tool("list_sandbox_ports") is not None
    with pytest.raises(ToolError):
        wire.call("list_sandbox_ports", sandbox_id="../other")
    assert wire.reads == 0


@pytest.mark.parametrize(
    "identifier",
    [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a%2fb",
        "a?x",
        "a#x",
        "a b",
        "a\n",
        " a",
        "a\u007f",
        "a\u0085",
        "a/../b",
    ],
)
def test_command_rejects_unsafe_identifiers(wire, identifier):
    from mcp.server.fastmcp.exceptions import ToolError

    with pytest.raises(ToolError):
        wire.call("run_sandbox_command", sandbox_id=identifier, command="pwd", confirm=True)
    assert wire.reads == 0
