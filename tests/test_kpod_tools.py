"""KPod catalog, public-exposure, and SDK wire-contract tests."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server
from krutrim_mcp_server.tools import CONFIRM_FIELD, REGION_FIELD


def _settings(**overrides: object) -> Settings:
    values = {
        "api_key": "test-api-key-for-offline-tests",
        "base_url": "https://cloud.olakrutrim.com",
        "default_region": "",
        "read_only": False,
        "log_level": "ERROR",
        "client_max_retries": 0,
        "tool_profile": "admin",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _create_args(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "pod_name": "mcp_pod",
        "pod_template_id": 1,
        "flavor_name": "A100-NVLINK-80G-Tiny",
        "sshkey_name": "mcp-ssh-key",
        "container_disk_size": "50",
        "volume_disk_size": "100",
        "volume_mount_path": "/workspace",
        "expose_http_ports": "8888",
        "expose_tcp_ports": "22",
        "allow_public_exposure": True,
        "has_encrypt_volume": True,
        "has_jupyter_notebook": True,
        "has_ssh_access": True,
        "environment_variables": [{"name": "MODEL_CACHE", "value": "/workspace/cache"}],
        "region": "In-Bangalore-1",
        "confirm": True,
    }
    values.update(overrides)
    return values


def _template_payload() -> list[dict[str, object]]:
    return [
        {
            "CreatedAt": "2026-08-08T00:00:00Z",
            "UpdatedAt": "2026-08-08T00:00:00Z",
            "DeletedAt": None,
            "ID": 1,
            "template_name": "KPod Tensorflow",
            "template_container_image_path": "tensorflow-notebook:cuda-python-3.11.10_v2.1",
            "template_container_start_command": "start-notebook.sh",
            "container_disk_size": "20",
            "volume_disk_size": "20",
            "volume_mount_path": "/workspace",
            "expose_http_ports": "8888",
            "expose_tcp_ports": "22",
            "enable_jupyter": False,
            "enable_ssh": False,
            "env_variables": None,
        }
    ]


def _flavor_payload() -> list[dict[str, object]]:
    return [
        {
            "groupBy": {
                "flavorid": "H100-NVLINK-Tiny",
                "flavorname": "H100-NVLINK-Tiny",
                "flavorstatus": "inactive",
                "cost": 42,
                "unit": "hour",
                "request_gpu_number": 0.125,
                "ram_size": 60,
                "vcpu_num": 16,
                "gpu_ram_size": 10,
            }
        },
        {
            "groupBy": {
                "flavorid": "A100-NVLINK-80G-Nano",
                "flavorname": "A100-NVLINK-80G-Nano",
                "flavorstatus": "active",
                "cost": 54,
                "unit": "hour",
                "request_gpu_number": 0.25,
                "ram_size": 60,
                "vcpu_num": 16,
                "gpu_ram_size": 20,
            }
        },
        {
            "groupBy": {
                "flavorid": "a100-live-flavor-id-tiny",
                "flavorname": "A100-NVLINK-80G-Tiny",
                "flavorstatus": "active",
                "cost": 33,
                "unit": "hour",
                "request_gpu_number": 0.125,
                "ram_size": 30,
                "vcpu_num": 16,
                "gpu_ram_size": 10,
            }
        },
    ]


def _gpu_resource_payload() -> dict[str, dict[str, str]]:
    return {
        "a100": {"tiny": "High", "nano": "Low"},
        "h100": {"tiny": "High"},
    }


def test_list_kpod_templates_uses_live_backend_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    payload = _template_payload()

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["query"] = request.url.query
        captured["authorization"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            text=json.dumps(payload),
            headers={"content-type": "text/plain; charset=utf-8"},
            request=request,
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    cloud_client = KrutrimClient(
        api_key="test-api-key",
        http_client=http_client,
        max_retries=0,
    )
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: cloud_client)
    tool = server._tool_manager.get_tool("list_kpod_templates")
    try:
        result = tool.fn()
    finally:
        cloud_client.close()

    assert tool is not None
    assert tool.annotations.readOnlyHint is True
    assert tool.parameters["properties"] == {}
    assert "live KPod templates" in tool.description
    assert captured == {
        "method": "GET",
        "path": "/v1/kpod/podtemplate",
        "query": b"",
        "authorization": "Bearer test-api-key",
    }
    assert result.ok is True
    assert result.data == {
        "live": True,
        "region_scoped": False,
        "selection_required": True,
        "count": 1,
        "templates": [
            {
                "pod_template_id": 1,
                "template_name": "KPod Tensorflow",
                "container_image_path": "tensorflow-notebook:cuda-python-3.11.10_v2.1",
                "container_start_command": "start-notebook.sh",
                "container_disk_size": "20",
                "volume_disk_size": "20",
                "volume_mount_path": "/workspace",
                "expose_http_ports": "8888",
                "expose_tcp_ports": "22",
                "has_jupyter_notebook": False,
                "has_ssh_access": False,
            }
        ],
    }


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ({"templates": []}, "expected list"),
        (["not-an-object"], "invalid entry object"),
        ([{**_template_payload()[0], "ID": True}], "invalid ID"),
        ([{**_template_payload()[0], "template_name": " "}], "invalid template_name"),
    ],
)
def test_list_kpod_templates_rejects_malformed_backend_catalog(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    error: str,
) -> None:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = payload
    cloud_client = MagicMock()
    cloud_client.get.return_value = response
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: cloud_client)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("list_kpod_templates").fn()

    cloud_client.get.assert_called_once_with(
        "/v1/kpod/podtemplate",
        cast_to=httpx.Response,
    )


def test_list_kpod_flavors_uses_live_backend_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(
            {
                "method": request.method,
                "path": request.url.path,
                "query": request.url.query,
                "authorization": request.headers.get("authorization"),
                "x_region": request.headers.get("x-region"),
            }
        )
        payload: object
        if request.url.path == "/api/v1/flavor/kpod":
            payload = _flavor_payload()
        else:
            payload = _gpu_resource_payload()
        return httpx.Response(200, json=payload, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    cloud_client = KrutrimClient(
        api_key="test-api-key",
        http_client=http_client,
        max_retries=0,
    )
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: cloud_client)
    tool = server._tool_manager.get_tool("list_kpod_flavors")
    try:
        result = tool.fn()
    finally:
        cloud_client.close()

    assert tool is not None
    assert tool.annotations.readOnlyHint is True
    assert tool.parameters["properties"] == {}
    assert "authenticated live KPod flavor" in tool.description
    assert captured == [
        {
            "method": "GET",
            "path": "/api/v1/flavor/kpod",
            "query": b"",
            "authorization": "Bearer test-api-key",
            "x_region": None,
        },
        {
            "method": "GET",
            "path": "/v2/kpod/gpuresource",
            "query": b"",
            "authorization": "Bearer test-api-key",
            "x_region": None,
        },
    ]
    assert result.ok is True
    assert result.data["catalog_type"] == "live_backend"
    assert result.data["live"] is True
    assert result.data["region_scoped"] is False
    assert result.data["live_availability_verified"] is True
    assert result.data["pricing_live_verified"] is True
    assert result.data["availability_is_snapshot"] is True
    assert result.data["count"] == 3
    assert result.data["selectable_count"] == 2
    assert [flavor["create_value"] for flavor in result.data["flavors"]] == [
        "A100-NVLINK-80G-Tiny",
        "A100-NVLINK-80G-Nano",
        "H100-NVLINK-Tiny",
    ]
    assert result.data["flavors"][0] == {
        "flavor_id": "a100-live-flavor-id-tiny",
        "name": "A100-NVLINK-80G-Tiny",
        "create_value": "A100-NVLINK-80G-Tiny",
        "gpu_family": "A100",
        "status": "active",
        "availability": "High",
        "availability_source_key": "tiny",
        "selectable": True,
        "on_demand_price_inr": 33,
        "billing_unit": "hour",
        "gpu_count": 0.125,
        "ram_gb": 30,
        "gpu_memory_gb": 10,
        "vcpus": 16,
    }
    assert result.data["flavors"][1]["availability"] == "Low"
    assert result.data["flavors"][1]["selectable"] is True
    assert result.data["flavors"][2]["availability"] == "Unavailable"
    assert result.data["flavors"][2]["selectable"] is False


@pytest.mark.parametrize(
    ("flavor_payload", "resource_payload", "error"),
    [
        ({"flavors": []}, _gpu_resource_payload(), "expected list"),
        (["not-an-object"], _gpu_resource_payload(), "invalid entry object"),
        (
            [{"groupBy": {**_flavor_payload()[0]["groupBy"], "cost": True}}],
            _gpu_resource_payload(),
            "invalid cost",
        ),
        (_flavor_payload(), {"a100": {}, "h100": []}, "mapping for h100"),
    ],
)
def test_list_kpod_flavors_rejects_malformed_live_catalogs(
    monkeypatch: pytest.MonkeyPatch,
    flavor_payload: object,
    resource_payload: object,
    error: str,
) -> None:
    cloud_client = MagicMock()
    flavor_response = MagicMock(spec=httpx.Response)
    flavor_response.status_code = 200
    flavor_response.json.return_value = flavor_payload
    resource_response = MagicMock(spec=httpx.Response)
    resource_response.status_code = 200
    resource_response.json.return_value = resource_payload
    cloud_client.get.side_effect = [flavor_response, resource_response]
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: cloud_client)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("list_kpod_flavors").fn()


def test_create_kpod_is_registered_as_guarded_public_create() -> None:
    server = create_server(_settings())
    tool = server._tool_manager.get_tool("create_kpod")

    assert tool is not None
    assert set(tool.parameters["required"]) == {
        "pod_name",
        "pod_template_id",
        "flavor_name",
        "sshkey_name",
        "container_disk_size",
        "volume_disk_size",
        "volume_mount_path",
        "expose_http_ports",
        "expose_tcp_ports",
        "has_jupyter_notebook",
        "has_ssh_access",
        "region",
        "confirm",
    }
    assert tool.parameters["properties"]["region"]["enum"] == [
        "In-Bangalore-1",
        "In-Hyderabad-1",
    ]
    assert tool.parameters["properties"]["allow_public_exposure"]["default"] is False
    assert (
        "publicly exposed" in tool.parameters["properties"]["allow_public_exposure"]["description"]
    )
    assert "list_kpod_templates" in tool.parameters["properties"]["pod_template_id"]["description"]
    assert (
        "Explicitly choose" in tool.parameters["properties"]["has_jupyter_notebook"]["description"]
    )
    assert "Explicitly choose" in tool.parameters["properties"]["has_ssh_access"]["description"]
    assert "category" not in tool.parameters["properties"]
    assert "publicly exposed KPod" in tool.description
    assert tool.annotations.readOnlyHint is False
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.idempotentHint is False


def test_repeated_server_registration_does_not_mutate_shared_fields() -> None:
    confirm_metadata_before = tuple(CONFIRM_FIELD.metadata)
    region_metadata_before = tuple(REGION_FIELD.metadata)

    for _ in range(12):
        create_server(_settings())

    assert tuple(CONFIRM_FIELD.metadata) == confirm_metadata_before
    assert tuple(REGION_FIELD.metadata) == region_metadata_before


@pytest.mark.parametrize(
    ("confirm", "allow_public_exposure", "error"),
    [
        (False, True, "confirm=true"),
        (True, False, "allow_public_exposure=true"),
    ],
)
def test_create_kpod_requires_confirmation_and_public_exposure_before_sdk(
    monkeypatch: pytest.MonkeyPatch,
    confirm: bool,
    allow_public_exposure: bool,
    error: str,
) -> None:
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("create_kpod").fn(
            **_create_args(
                confirm=confirm,
                allow_public_exposure=allow_public_exposure,
            )
        )

    get_client.assert_not_called()


def test_create_kpod_omitted_public_exposure_fails_closed_before_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)
    arguments = _create_args()
    arguments.pop("allow_public_exposure")

    with pytest.raises(ToolError, match="allow_public_exposure=true"):
        server._tool_manager.get_tool("create_kpod").fn(**arguments)

    get_client.assert_not_called()


@pytest.mark.parametrize("invalid_acknowledgement", ["yes", 1])
def test_create_kpod_direct_call_rejects_non_boolean_public_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
    invalid_acknowledgement: object,
) -> None:
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match="allow_public_exposure=true"):
        server._tool_manager.get_tool("create_kpod").fn(
            **_create_args(allow_public_exposure=invalid_acknowledgement)
        )

    get_client.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("allow_public_exposure", "yes"),
        ("allow_public_exposure", 1),
        ("confirm", "yes"),
        ("confirm", 1),
    ],
)
async def test_create_kpod_protocol_requires_literal_boolean_acknowledgements(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    invalid_value: object,
) -> None:
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)
    arguments = _create_args()
    arguments[field] = invalid_value

    async with create_connected_server_and_client_session(server._mcp_server) as session:
        await session.initialize()
        result = await session.call_tool("create_kpod", arguments)

    assert result.isError is True
    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("field", "invalid_value", "error"),
    [
        ("pod_template_id", True, "pod_template_id must be an integer"),
        ("has_encrypt_volume", "false", "has_encrypt_volume must be a JSON boolean"),
        ("has_jupyter_notebook", "yes", "has_jupyter_notebook must be a JSON boolean"),
        ("has_ssh_access", 1, "has_ssh_access must be a JSON boolean"),
    ],
)
def test_create_kpod_direct_call_rejects_coerced_template_and_feature_flags(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    invalid_value: object,
    error: str,
) -> None:
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("create_kpod").fn(**_create_args(**{field: invalid_value}))

    get_client.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("pod_template_id", True),
        ("has_encrypt_volume", "false"),
        ("has_jupyter_notebook", "yes"),
        ("has_ssh_access", 1),
    ],
)
async def test_create_kpod_protocol_rejects_coerced_template_and_feature_flags(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    invalid_value: object,
) -> None:
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)
    arguments = _create_args()
    arguments[field] = invalid_value

    async with create_connected_server_and_client_session(server._mcp_server) as session:
        await session.initialize()
        result = await session.call_tool("create_kpod", arguments)

    assert result.isError is True
    get_client.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_field", ["has_jupyter_notebook", "has_ssh_access"])
async def test_create_kpod_protocol_requires_explicit_feature_choices(
    monkeypatch: pytest.MonkeyPatch,
    missing_field: str,
) -> None:
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)
    arguments = _create_args()
    arguments.pop(missing_field)

    async with create_connected_server_and_client_session(server._mcp_server) as session:
        await session.initialize()
        result = await session.call_tool("create_kpod", arguments)

    assert result.isError is True
    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("http_ports", "tcp_ports", "error"),
    [
        ("", "22", "comma-separated list"),
        ("8888", " ", "comma-separated list"),
        ("8888,", "22", "comma-separated list"),
        ("http", "22", "numeric ports"),
        ("8888", "0", "between 1 and 65535"),
        ("65536", "22", "between 1 and 65535"),
    ],
)
def test_create_kpod_rejects_invalid_public_ports_before_sdk(
    monkeypatch: pytest.MonkeyPatch,
    http_ports: str,
    tcp_ports: str,
    error: str,
) -> None:
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("create_kpod").fn(
            **_create_args(
                expose_http_ports=http_ports,
                expose_tcp_ports=tcp_ports,
            )
        )

    get_client.assert_not_called()


@pytest.mark.parametrize(
    "pod_name",
    [" mcp-pod", "mcp-pod ", "mcp.pod", "x" * 33],
)
def test_create_kpod_rejects_names_outside_portal_contract_before_sdk(
    monkeypatch: pytest.MonkeyPatch,
    pod_name: str,
) -> None:
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match="pod_name must be 1-32 characters"):
        server._tool_manager.get_tool("create_kpod").fn(**_create_args(pod_name=pod_name))

    get_client.assert_not_called()


def test_create_kpod_respects_read_only_lock_before_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = create_server(_settings(read_only=True))
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match="KRUTRIM_MCP_READ_ONLY=true"):
        server._tool_manager.get_tool("create_kpod").fn(**_create_args())

    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("has_jupyter_notebook", "has_ssh_access"),
    [(True, True), (False, False)],
)
def test_create_kpod_uses_official_sdk_wire_contract(
    monkeypatch: pytest.MonkeyPatch,
    has_jupyter_notebook: bool,
    has_ssh_access: bool,
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/flavor/kpod":
            return httpx.Response(200, json=_flavor_payload(), request=request)
        if request.url.path == "/v2/kpod/gpuresource":
            return httpx.Response(200, json=_gpu_resource_payload(), request=request)
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={"message": "Pod creation accepted", "pod_id": "kpod-1"},
            request=request,
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    cloud_client = KrutrimClient(
        api_key="test-api-key",
        http_client=http_client,
        max_retries=0,
    )
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: cloud_client)
    try:
        result = server._tool_manager.get_tool("create_kpod").fn(
            **_create_args(
                has_jupyter_notebook=has_jupyter_notebook,
                has_ssh_access=has_ssh_access,
            )
        )
    finally:
        cloud_client.close()

    assert result.ok is True
    assert result.data == {"message": "Pod creation accepted", "pod_id": "kpod-1"}
    assert captured == {
        "method": "POST",
        "path": "/v1/kpod/pod",
        "body": {
            "category": "aipod",
            "container_disk_size": "50",
            "expose_http_ports": "8888",
            "expose_tcp_ports": "22",
            "flavor_name": "A100-NVLINK-80G-Tiny",
            "has_encrypt_volume": True,
            "has_jupyter_notebook": has_jupyter_notebook,
            "has_ssh_access": has_ssh_access,
            "pod_name": "mcp_pod",
            "pod_template_id": 1,
            "region": "In-Bangalore-1",
            "sshkey_name": "mcp-ssh-key",
            "volume_disk_size": "100",
            "volume_mount_path": "/workspace",
            "environment_variables": [{"name": "MODEL_CACHE", "value": "/workspace/cache"}],
        },
    }


def test_create_kpod_sends_empty_environment_variables_when_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/flavor/kpod":
            return httpx.Response(200, json=_flavor_payload(), request=request)
        if request.url.path == "/v2/kpod/gpuresource":
            return httpx.Response(200, json=_gpu_resource_payload(), request=request)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={"message": "Pod creation accepted", "pod_id": "kpod-1"},
            request=request,
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    cloud_client = KrutrimClient(
        api_key="test-api-key",
        http_client=http_client,
        max_retries=0,
    )
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: cloud_client)
    arguments = _create_args()
    arguments.pop("environment_variables")
    try:
        result = server._tool_manager.get_tool("create_kpod").fn(**arguments)
    finally:
        cloud_client.close()

    assert result.ok is True
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["environment_variables"] == []


@pytest.mark.parametrize(
    ("flavor_name", "flavor_status", "availability", "error"),
    [
        (
            "A100-NVLINK-Tiny",
            "active",
            "High",
            "not in the current live catalog",
        ),
        (
            "A100-NVLINK-80G-Tiny",
            "inactive",
            "High",
            "not currently selectable",
        ),
        (
            "A100-NVLINK-80G-Tiny",
            "active",
            "Unavailable",
            "not currently selectable",
        ),
        (
            "A100-NVLINK-80G-Tiny",
            "active",
            None,
            "not currently selectable",
        ),
    ],
)
def test_create_kpod_fails_closed_on_stale_or_unavailable_flavor(
    monkeypatch: pytest.MonkeyPatch,
    flavor_name: str,
    flavor_status: str,
    availability: str | None,
    error: str,
) -> None:
    payload = _flavor_payload()
    payload[2]["groupBy"]["flavorstatus"] = flavor_status  # type: ignore[index]
    resource_payload = _gpu_resource_payload()
    if availability is None:
        resource_payload["a100"].pop("tiny")
    else:
        resource_payload["a100"]["tiny"] = availability
    client = MagicMock()
    flavor_response = MagicMock(spec=httpx.Response)
    flavor_response.status_code = 200
    flavor_response.json.return_value = payload
    resource_response = MagicMock(spec=httpx.Response)
    resource_response.status_code = 200
    resource_response.json.return_value = resource_payload
    client.get.side_effect = [flavor_response, resource_response]
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("create_kpod").fn(**_create_args(flavor_name=flavor_name))

    client.kpod.pod.create.assert_not_called()


def test_create_kpod_rejects_duplicate_live_create_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _flavor_payload()
    duplicate = {
        "groupBy": {
            **payload[2]["groupBy"],  # type: ignore[dict-item]
            "flavorid": "a100-duplicate-live-flavor-id",
        }
    }
    payload.append(duplicate)
    client = MagicMock()
    flavor_response = MagicMock(spec=httpx.Response)
    flavor_response.status_code = 200
    flavor_response.json.return_value = payload
    resource_response = MagicMock(spec=httpx.Response)
    resource_response.status_code = 200
    resource_response.json.return_value = _gpu_resource_payload()
    client.get.side_effect = [flavor_response, resource_response]
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)

    with pytest.raises(ToolError, match="ambiguous in the current live catalog"):
        server._tool_manager.get_tool("create_kpod").fn(**_create_args())

    client.kpod.pod.create.assert_not_called()
