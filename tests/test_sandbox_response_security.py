"""Offline regression coverage for shared Sandbox response safety boundaries."""

import warnings
from datetime import datetime
from types import SimpleNamespace

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.server import Settings as FastMCPSettings

from krutrim_mcp_server.tools.sandbox import execution, files, lifecycle

# Each malformed field is accepted by SDK construction but violates its model.
CASES = [
    ("describe_sandbox", {}, {"ttlSeconds": {"secret": "opaque-warning-secret"}}),
    (
        "set_sandbox_ttl",
        {"ttl_seconds": 60, "confirm": True},
        {"ttlSeconds": {"secret": "opaque-warning-secret"}},
    ),
    ("delete_sandbox", {"confirm": True}, {"id": {"secret": "opaque-warning-secret"}}),
    (
        "create_sandbox",
        {
            "sandbox_name": "demo",
            "region": "In-Bangalore-1",
            "flavor_name": "cpu-small",
            "ttl_seconds": 60,
            "template_id": 17,
            "confirm": True,
        },
        {"id": {"secret": "opaque-warning-secret"}},
    ),
    (
        "list_sandboxes",
        {"region": "In-Bangalore-1"},
        {"rows": [{"ttlSeconds": {"secret": "opaque-warning-secret"}}]},
    ),
    (
        "list_sandbox_flavors",
        {"region": "In-Bangalore-1"},
        [{"name": {"secret": "opaque-warning-secret"}}],
    ),
    (
        "stat_sandbox_file",
        {"path": "/workspace/a.txt"},
        {"size": {"secret": "opaque-warning-secret"}},
    ),
    ("list_sandbox_files", {"path": "/workspace"}, [{"size": {"secret": "opaque-warning-secret"}}]),
    (
        "write_sandbox_file",
        {"path": "/workspace/a.txt", "content": "opaque-warning-secret", "confirm": True},
        {"path": {"secret": "opaque-warning-secret"}},
    ),
    (
        "move_sandbox_file",
        {"path": "/workspace/a.txt", "new_path": "/workspace/b.txt", "confirm": True},
        {"path": {"secret": "opaque-warning-secret"}},
    ),
    (
        "make_sandbox_directory",
        {"path": "/workspace/dir", "confirm": True},
        {"path": {"secret": "opaque-warning-secret"}},
    ),
    (
        "delete_sandbox_file",
        {"path": "/workspace/a.txt", "confirm": True},
        {"path": {"secret": "opaque-warning-secret"}},
    ),
    (
        "run_sandbox_command",
        {"command": "pwd", "confirm": True},
        {"exitCode": {"secret": "opaque-warning-secret"}},
    ),
    (
        "open_sandbox_port",
        {"port": 8080, "confirm": True, "allow_public_exposure": True},
        {"port": {"secret": "opaque-warning-secret"}},
    ),
    ("list_sandbox_ports", {}, [{"port": {"secret": "opaque-warning-secret"}}]),
]


@pytest.fixture
def wire(monkeypatch):
    state = SimpleNamespace(tool=None, data=None, status=200, message=None, requests=[])

    def handler(request):
        state.requests.append(request)
        if request.url.path.endswith("/template"):
            return httpx.Response(200, json=[{"ID": 17, "template_name": "python"}])
        if state.tool == "create_sandbox" and request.url.path.endswith("/flavors"):
            return httpx.Response(
                200,
                json={
                    "status": 200,
                    "data": [{"name": "cpu-small", "groupBy": {"flavorStatus": "active"}}],
                },
            )
        return httpx.Response(
            200, json={"status": state.status, "data": state.data, "message": state.message}
        )

    with KrutrimClient(
        api_key="offline-test",
        base_url="https://sandbox.invalid",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    ) as client:
        session = SimpleNamespace(get_client=lambda: client)
        FastMCPSettings.model_rebuild()
        mcp = FastMCP("sandbox-response-security")
        for module in (lifecycle, files, execution):
            monkeypatch.setattr(module, "get_session", lambda: session)
            monkeypatch.setattr(module, "settings", lambda: SimpleNamespace(read_only=False))
            module.register(mcp)

        def call(name, args):
            state.tool = name
            if name not in {"create_sandbox", "list_sandboxes", "list_sandbox_flavors"}:
                args = {"sandbox_id": "sb-1", **args}
            return mcp._tool_manager.get_tool(name).fn(**args)

        state.call = call
        yield state


@pytest.mark.parametrize("name,args,data", CASES, ids=[case[0] for case in CASES])
def test_malformed_models_fail_without_warnings_or_secret_reflection(wire, name, args, data):
    wire.data = data
    error = None
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            wire.call(name, args)
        except ToolError as exc:
            error = exc
    assert not caught, [str(item.message) for item in caught]
    assert error is not None, "Malformed Sandbox model must fail through the MCP error channel"
    assert "opaque-warning-secret" not in str(error)
    assert "withheld" in str(error)


def test_lifecycle_serialization_errors_do_not_escape_protected_wrapper(wire, monkeypatch):
    from krutrim_client.types.sandbox import SandboxGetResponse

    def fail_serialization(*args, **kwargs):
        raise ValueError("opaque-serialization-secret")

    wire.data = {"id": "sb-1"}
    monkeypatch.setattr(SandboxGetResponse, "model_dump", fail_serialization)
    with pytest.raises(ToolError) as error:
        wire.call("describe_sandbox", {})
    assert "opaque-serialization-secret" not in str(error.value)
    assert "withheld" in str(error.value)


@pytest.mark.parametrize("name,args,data", CASES, ids=[case[0] for case in CASES])
@pytest.mark.parametrize("status", [400, 500, "500", True, "opaque-envelope-secret"])
def test_failed_or_invalid_envelopes_use_safe_mcp_errors(wire, name, args, data, status):
    wire.status = status
    wire.message = "echo opaque-envelope-secret"
    with pytest.raises(ToolError) as error:
        wire.call(name, args)
    assert "opaque-envelope-secret" not in str(error.value)
    assert "withheld" in str(error.value)
    assert len(wire.requests) == (3 if name == "create_sandbox" else 1)


def _call_with_secrets(wire, name, secrets):
    environment = {f"CUSTOM_{index}": secret for index, secret in enumerate(secrets)}
    if name == "create_sandbox":
        args = {
            "sandbox_name": "demo",
            "region": "In-Bangalore-1",
            "flavor_name": "cpu-small",
            "ttl_seconds": 60,
            "template_id": 17,
            "confirm": True,
            "environment_variables": environment,
        }
    elif name == "run_sandbox_command":
        args = {"command": "env", "confirm": True, "envs": environment}
    else:
        assert name == "write_sandbox_file"
        (content,) = secrets
        args = {"path": "/a", "content": content, "confirm": True}
    return wire.call(name, args)


@pytest.mark.parametrize("name", ["create_sandbox", "run_sandbox_command"])
@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reverse"])
@pytest.mark.parametrize(
    "secrets,text,expected",
    [
        (
            ["secret-left-SHARED", "SHARED-secret-right", ""],
            "secret-left-SHARED-secret-right",
            "***REDACTED***",
        ),
        (
            ["secret-left-SHARED", "SHARED-secret-right"],
            "secret-left-SHARED-secret-right / secret-left-SHARED-secret-right",
            "***REDACTED*** / ***REDACTED***",
        ),
        (
            ["opaque-prefix", "opaque-prefix-private-suffix"],
            "opaque-prefix-private-suffix / opaque-prefix",
            "***REDACTED*** / ***REDACTED***",
        ),
        (
            ["opaque-left", "opaque-right"],
            "opaque-leftopaque-right",
            "***REDACTED******REDACTED***",
        ),
        (["ababa", ""], "abababa", "***REDACTED***"),
    ],
    ids=["partial-overlap", "repeated-overlap", "contained", "adjacent", "self-overlap"],
)
def test_environment_secret_spans_use_original_text(wire, name, reverse, secrets, text, expected):
    wire.data = {"stdout": text, "nested": [{"echo": text}], "id": "sb-1"}
    wire.message = text
    result = _call_with_secrets(wire, name, secrets[::-1] if reverse else secrets)
    assert result.ok is True
    assert result.data["data"]["stdout"] == expected
    assert result.data["data"]["nested"] == [{"echo": expected}]
    if name == "create_sandbox":
        assert result.data["message"] == expected


@pytest.mark.parametrize("name", ["create_sandbox", "run_sandbox_command", "write_sandbox_file"])
@pytest.mark.parametrize(
    "secret",
    [
        "private-prefix Bearer token private-suffix",
        "private-prefix eyJhbGciOiJub25lIn0.eyJzdWIiOiJvZmZsaW5lIn0.signature private-suffix",
        "private-prefix password=opaque-value private-suffix",
    ],
    ids=["bearer", "jwt", "assignment"],
)
def test_known_secrets_are_removed_before_generic_redaction(wire, name, secret):
    wire.data = {"path": "/a", "stdout": secret, "nested": [{"echo": secret}]}
    wire.message = secret
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = _call_with_secrets(wire, name, [secret])
    assert not caught
    assert result.data["data"]["stdout"] == "***REDACTED***"
    assert result.data["data"]["nested"] == [{"echo": "***REDACTED***"}]
    assert "private-prefix" not in result.model_dump_json()
    assert "private-suffix" not in result.model_dump_json()


@pytest.mark.parametrize("name", ["create_sandbox", "run_sandbox_command", "write_sandbox_file"])
@pytest.mark.parametrize("nested", [False, True], ids=["data-extra-key", "nested-extra-key"])
def test_supplied_secrets_redacted_from_sdk_extra_keys(wire, name, nested):
    secret = "opaque-upload-key-secret" if name == "write_sandbox_file" else "opaque-env-key-secret"
    echoed = {secret: "echo", "unrelated": "keep"}
    wire.data = {"path": "/a", **({"nested": [echoed]} if nested else echoed)}
    result = _call_with_secrets(wire, name, [secret])
    assert result.ok is True
    assert secret not in result.model_dump_json()
    data = result.data["data"]
    assert data["path"] == "/a"
    redacted = data["nested"][0] if nested else data
    assert redacted["***REDACTED***"] == "echo"
    assert redacted["unrelated"] == "keep"


@pytest.mark.parametrize("name", ["describe_sandbox", "list_sandboxes", "set_sandbox_ttl"])
def test_sdk_timestamps_and_nested_aliases_survive_strict_response_validation(wire, name):
    timestamp = "2026-01-02T03:04:05+00:00"
    data = {"id": "sb-1", "ttlSeconds": 60, "expiresAt": timestamp}
    if name != "set_sandbox_ttl":
        data.update({
            "createdAt": timestamp,
            "updatedAt": timestamp,
            "networkStorages": [{
                "networkStorageId": "storage-1",
                "networkStorageMountPath": "/mnt/data",
                "networkStorageReadOnly": True,
            }],
        })
    wire.data = {"rows": [data], "totalPages": 2} if name == "list_sandboxes" else data
    args = {
        "describe_sandbox": {},
        "list_sandboxes": {"region": "In-Bangalore-1"},
        "set_sandbox_ttl": {"ttl_seconds": 60, "confirm": True},
    }[name]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = wire.call(name, args)
    assert not caught
    assert result.ok is True
    actual = result.data["data"]
    if name == "list_sandboxes":
        assert actual["total_pages"] == 2
        actual = actual["rows"][0]
    assert actual["ttl_seconds"] == 60
    assert datetime.fromisoformat(
        actual["expires_at"].replace("Z", "+00:00")
    ) == datetime.fromisoformat(timestamp)
    if name != "set_sandbox_ttl":
        assert actual["created_at"] == actual["expires_at"] == actual["updated_at"]
        assert actual["network_storages"] == [{
            "network_storage_id": "storage-1",
            "network_storage_mount_path": "/mnt/data",
            "network_storage_read_only": True,
        }]
