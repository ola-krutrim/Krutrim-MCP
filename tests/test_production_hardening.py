"""Local stdio catalog, SDK compatibility, and safety regression tests."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock

import httpx
import pytest
from krutrim_client import KrutrimClient
from krutrim_client.types.kbs.volume_details import VolumeDetail
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.profiles import GuardedFastMCP
from krutrim_mcp_server.serialize import to_jsonable
from krutrim_mcp_server.server import create_server, main
from tests.auth_tokens import (
    TEST_ACCESS_TOKEN,
    TEST_REFRESH_TOKEN,
    make_iam_token_pair,
)

_VOLUME_KRN = (
    "krn:kbs:In-Bangalore-1:customer-test:account-test:volume:"
    "00000000-0000-4000-8000-000000000001"
)
_VPC_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:vpc:"
    "00000000-0000-4000-8000-000000000002"
)
_IMAGE_KRN = (
    "krn:vm:In-Bangalore-1:default:default:image:"
    "00000000-0000-4000-8000-000000000005"
)
_SNAPSHOT_KRN = (
    "krn:kbs:In-Bangalore-1:customer-test:account-test:snapshot:"
    "00000000-0000-4000-8000-000000000003"
)
_BACKUP_ID = "backup-00000000-0000-4000-8000-000000000004"


def _jwt(payload: dict[str, object]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    segments = []
    for part in (header, payload):
        encoded = base64.urlsafe_b64encode(json.dumps(part).encode()).decode()
        segments.append(encoded.rstrip("="))
    signature = base64.urlsafe_b64encode(b"test-signature").decode().rstrip("=")
    return ".".join([*segments, signature])


_TEST_IAM_JWT = TEST_ACCESS_TOKEN
_TEST_REFRESH_TOKEN = TEST_REFRESH_TOKEN


def _configure_bearer_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "KRUTRIM_API_KEY",
        "KRUTRIM_CLIENT_API_KEY",
        "krutrim_client_API_KEY",
        "KRUTRIMCLIENT_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", _TEST_IAM_JWT)
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", _TEST_REFRESH_TOKEN)


def _compute_flavor_entry(
    *,
    name: str = "CPU-2x-8GB",
    region: str = "In-Bangalore-1",
    flavor_id: str = "11111111-1111-4111-8111-111111111111",
    cpus: object = "2",
    memory_gb: object = "8",
    cost: object = "6",
    currency: object = "INR",
    unit: object = "hour",
    status: str = "active",
    flavor_type: str = "CPU",
) -> dict[str, object]:
    return {
        "subject": region,
        "groupBy": {
            "flavorid": flavor_id,
            "flavorname": name,
            "cpus": cpus,
            "cpuram": memory_gb,
            "cost": cost,
            "currency": currency,
            "unit": unit,
            "flavorstatus": status,
            "type": flavor_type,
        },
    }


def _configure_compute_flavor_catalog(
    mock_client: MagicMock,
    entries: list[object] | None = None,
) -> None:
    request = httpx.Request(
        "GET",
        "https://cloud.olakrutrim.com/api/v1/flavor/compute?type=CPU",
    )
    mock_client.get.return_value = httpx.Response(
        200,
        json=[_compute_flavor_entry()] if entries is None else entries,
        request=request,
    )


def _settings(**overrides: object) -> Settings:
    values = dict(
        api_key=None,
        base_url="https://cloud.olakrutrim.com",
        default_region="",
        read_only=False,
        log_level="ERROR",
        client_max_retries=0,
        tool_profile="core-readonly",
        access_token=_TEST_IAM_JWT,
        refresh_token=_TEST_REFRESH_TOKEN,
    )
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_unified_catalog_includes_all_supported_tools() -> None:
    normal = create_server(_settings(tool_profile="all"))
    normal_names = {tool.name for tool in normal._tool_manager.list_tools()}
    assert "get_iam_role" in normal_names
    assert "list_storage_access_keys" in normal_names
    assert "create_storage_access_key" in normal_names
    assert "force_delete_volume" in normal_names
    assert "get_kks_kubeconfig" in normal_names
    assert "create_iam_user" in normal_names
    assert "create_asg" not in normal_names
    assert "create_launch_template" not in normal_names
    assert "create_kpod" in normal_names
    assert "list_kpod_flavors" in normal_names
    assert "list_kpod_templates" in normal_names
    assert "validate_dns_zone_vpc" not in normal_names
    assert len(normal_names) == 138

    legacy_profile = create_server(_settings(tool_profile="core-readonly"))
    legacy_names = {tool.name for tool in legacy_profile._tool_manager.list_tools()}
    assert legacy_names == normal_names



def test_compute_flavor_discovery_schema_and_wire_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    payload = [
        _compute_flavor_entry(
            name="CPU-4x-16GB",
            flavor_id="44444444-4444-4444-8444-444444444444",
            cpus="4",
            memory_gb="16",
            status="inactive",
        ),
        _compute_flavor_entry(
            name="CPU-1x-4GB",
            flavor_id="11111111-1111-4111-8111-111111111111",
            cpus=1,
            memory_gb=4,
        ),
        _compute_flavor_entry(region="In-Hyderabad-1"),
        _compute_flavor_entry(name="GPU-1x", flavor_type="GPU"),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["type"] = request.url.params.get("type")
        captured["region"] = request.headers.get("x-region")
        return httpx.Response(200, json=payload, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    cloud_client = KrutrimClient(
        api_key="test",
        http_client=http_client,
        max_retries=0,
    )
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: cloud_client)
    try:
        list_tool = server._tool_manager.get_tool("list_compute_flavors")
        create_tool = server._tool_manager.get_tool("create_instance")

        assert set(list_tool.parameters["required"]) == {"region"}
        assert list_tool.annotations.readOnlyHint is True
        assert create_tool.parameters["properties"]["instance_type"]["minLength"] == 1
        assert "instance_type" in create_tool.parameters["required"]
        assert "default" not in create_tool.parameters["properties"]["instance_type"]
        assert "list_compute_flavors" in create_tool.description
        assert "cpu-standard" not in create_tool.description.lower()

        result = list_tool.fn(region="In-Bangalore-1")

        assert result.ok is True
        assert result.data == {
            "region": "In-Bangalore-1",
            "flavor_type": "CPU",
            "selection_required": True,
            "flavors": [
                {
                    "id": "11111111-1111-4111-8111-111111111111",
                    "name": "CPU-1x-4GB",
                    "vcpus": 1,
                    "memory_gb": 4,
                    "cost": "6",
                    "currency": "INR",
                    "unit": "hour",
                    "status": "active",
                    "selectable": True,
                },
                {
                    "id": "44444444-4444-4444-8444-444444444444",
                    "name": "CPU-4x-16GB",
                    "vcpus": 4,
                    "memory_gb": 16,
                    "cost": "6",
                    "currency": "INR",
                    "unit": "hour",
                    "status": "inactive",
                    "selectable": False,
                },
            ],
        }
        assert captured == {
            "path": "/api/v1/flavor/compute",
            "type": "CPU",
            "region": "In-Bangalore-1",
        }
    finally:
        cloud_client.close()


def test_gpu_compute_flavor_discovery_schema_and_wire_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    payload = [
        _compute_flavor_entry(name="CPU-1x-4GB", flavor_type="CPU"),
        _compute_flavor_entry(
            name="A100-NVLINK-Standard-1x",
            flavor_id="99999999-9999-4999-8999-999999999999",
            cpus="16",
            memory_gb="120",
            cost=125,
            flavor_type="GPU",
        ),
        _compute_flavor_entry(
            name="A100-HYD-1x",
            region="In-Hyderabad-1",
            flavor_type="GPU",
        ),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["type"] = request.url.params.get("type")
        captured["region"] = request.headers.get("x-region")
        return httpx.Response(200, json=payload, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    cloud_client = KrutrimClient(
        api_key="test",
        http_client=http_client,
        max_retries=0,
    )
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: cloud_client)
    try:
        list_tool = server._tool_manager.get_tool("list_gpu_compute_flavors")
        create_tool = server._tool_manager.get_tool("create_instance")

        assert set(list_tool.parameters["required"]) == {"region"}
        assert list_tool.annotations.readOnlyHint is True
        assert create_tool.parameters["properties"]["instance_flavor_type"]["default"] == "CPU"

        result = list_tool.fn(region="In-Bangalore-1")

        assert result.ok is True
        assert result.data == {
            "region": "In-Bangalore-1",
            "flavor_type": "GPU",
            "selection_required": True,
            "flavors": [
                {
                    "id": "99999999-9999-4999-8999-999999999999",
                    "name": "A100-NVLINK-Standard-1x",
                    "vcpus": 16,
                    "memory_gb": 120,
                    "cost": "125",
                    "currency": "INR",
                    "unit": "hour",
                    "status": "active",
                    "selectable": True,
                },
            ],
        }
        assert captured == {
            "path": "/api/v1/flavor/compute",
            "type": "GPU",
            "region": "In-Bangalore-1",
        }
    finally:
        cloud_client.close()


@pytest.mark.parametrize(
    ("entries", "instance_type", "region"),
    [
        ([_compute_flavor_entry()], "cpu-2x-8gb", "In-Bangalore-1"),
        (
            [_compute_flavor_entry(status="inactive")],
            "CPU-2x-8GB",
            "In-Bangalore-1",
        ),
        ([_compute_flavor_entry()], "CPU-2x-8GB", "In-Hyderabad-1"),
        ([], "CPU-2x-8GB", "In-Bangalore-1"),
    ],
)
def test_create_instance_rejects_unselected_or_unavailable_flavor_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    entries: list[dict[str, object]],
    instance_type: str,
    region: str,
) -> None:
    mock_client = MagicMock()
    _configure_compute_flavor_catalog(mock_client, entries)
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    with pytest.raises(ToolError, match="No default or fallback flavor was applied"):
        server._tool_manager.get_tool("create_instance").fn(
            instance_name="vm-invalid-flavor",
            instance_type=instance_type,
            vpc_id="vpc-1",
            subnet_id="subnet-1",
            ssh_key_name="ssh-key-1",
            security_group_ids=["sg-1"],
            image_krn="image-1",
            region=region,
            confirm=True,
        )

    mock_client.highlvlvpc.create_instance.assert_not_called()


def test_create_instance_accepts_explicit_gpu_flavor_after_catalog_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.create_instance.return_value = {"instanceKrn": "vm-1"}
    _configure_compute_flavor_catalog(
        mock_client,
        [
            _compute_flavor_entry(name="CPU-2x-8GB", flavor_type="CPU"),
            _compute_flavor_entry(
                name="A100-NVLINK-Standard-1x",
                flavor_type="GPU",
                cpus="16",
                memory_gb="120",
            ),
        ],
    )
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    result = server._tool_manager.get_tool("create_instance").fn(
        instance_name="vm-gpu",
        instance_type="A100-NVLINK-Standard-1x",
        instance_flavor_type="GPU",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        ssh_key_name="ssh-key-1",
        security_group_ids=["sg-1"],
        image_krn="image-1",
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    assert mock_client.get.call_args.kwargs["options"]["params"] == {"type": "GPU"}
    assert (
        mock_client.highlvlvpc.create_instance.call_args.kwargs["instanceType"]
        == "A100-NVLINK-Standard-1x"
    )
    assert mock_client.highlvlvpc.create_instance.call_args.kwargs["isGpu"] is True
    assert mock_client.highlvlvpc.create_instance.call_args.kwargs["count"] == 1


def test_create_instance_blocks_malformed_flavor_catalog_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    malformed = _compute_flavor_entry()
    group_by = malformed["groupBy"]
    assert isinstance(group_by, dict)
    del group_by["flavorid"]
    _configure_compute_flavor_catalog(mock_client, [malformed])
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    with pytest.raises(ToolError, match="without required fields: flavorid"):
        server._tool_manager.get_tool("create_instance").fn(
            instance_name="vm-malformed-catalog",
            instance_type="CPU-2x-8GB",
            vpc_id="vpc-1",
            subnet_id="subnet-1",
            ssh_key_name="ssh-key-1",
            security_group_ids=["sg-1"],
            image_krn="image-1",
            region="In-Bangalore-1",
            confirm=True,
        )

    mock_client.highlvlvpc.create_instance.assert_not_called()


@pytest.mark.parametrize(
    ("entries", "error"),
    [
        ([None], "invalid entry object at index 0"),
        ([{}], "index 0 with an invalid subject"),
        (
            [_compute_flavor_entry(), None],
            "invalid entry object at index 1",
        ),
        (
            [{"subject": "In-Bangalore-1", "groupBy": {}}],
            "index 0 with an invalid groupBy.type",
        ),
    ],
)
def test_create_instance_blocks_malformed_flavor_catalog_envelopes(
    monkeypatch: pytest.MonkeyPatch,
    entries: list[object],
    error: str,
) -> None:
    mock_client = MagicMock()
    _configure_compute_flavor_catalog(mock_client, entries)
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("create_instance").fn(
            instance_name="vm-malformed-envelope",
            instance_type="CPU-2x-8GB",
            vpc_id="vpc-1",
            subnet_id="subnet-1",
            ssh_key_name="ssh-key-1",
            security_group_ids=["sg-1"],
            image_krn="image-1",
            region="In-Bangalore-1",
            confirm=True,
        )

    mock_client.highlvlvpc.create_instance.assert_not_called()


def test_snapshot_and_backup_schemas_are_explicit_non_idempotent_creates() -> None:
    server = create_server(_settings(tool_profile="storage"))
    assert len(server._tool_manager.list_tools()) == 138
    snapshot = server._tool_manager.get_tool("create_volume_snapshot")
    backup = server._tool_manager.get_tool("create_volume_backup")

    for tool in (snapshot, backup):
        assert {"name", "volume_id", "vpc_krn", "region", "confirm"}.issubset(
            tool.parameters["required"]
        )
        properties = tool.parameters["properties"]
        assert properties["name"]["minLength"] == 3
        assert properties["name"]["maxLength"] == 63
        assert "[.-][a-z0-9]" in properties["name"]["pattern"]
        assert properties["volume_id"]["minLength"] == 1
        assert properties["volume_id"]["pattern"].startswith("^krn:kbs:")
        assert properties["vpc_krn"]["pattern"].startswith("^krn:vpc:")
        assert properties["allow_attached_volume"]["default"] is False
        assert "force" not in properties
        assert "metadata" not in properties
        assert tool.annotations.readOnlyHint is False
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.idempotentHint is False
        assert tool.annotations.openWorldHint is True

    assert "backup_type" not in backup.parameters["properties"]


def test_standalone_volume_schema_matches_current_kbs_and_vm_type_contracts() -> None:
    storage_server = create_server(_settings(tool_profile="storage"))
    volume = storage_server._tool_manager.get_tool("create_volume")
    properties = volume.parameters["properties"]

    assert set(volume.parameters["required"]) == {
        "name",
        "size_gb",
        "vpc_krn",
        "region",
        "confirm",
    }
    assert "availability_zone" not in properties
    assert "tenant_id" not in properties
    assert properties["source_type"]["anyOf"][0]["enum"] == [
        "image",
        "volume",
        "snapshot",
    ]
    assert properties["source_id"]["anyOf"][0]["pattern"].startswith("^(?:krn:vm:")
    assert "KBS volume" in properties["source_id"]["anyOf"][0]["description"]
    assert properties["size_gb"]["minimum"] == 1
    assert "maximum" not in properties["size_gb"]
    assert properties["volume_type"]["enum"] == ["HNSS", "HNSS_Encrypted"]
    assert properties["volume_type"]["default"] == "HNSS"
    assert properties["multiattach"]["default"] is False
    assert volume.annotations.readOnlyHint is False
    assert volume.annotations.destructiveHint is False
    assert volume.annotations.idempotentHint is False
    assert volume.annotations.openWorldHint is True

    compute_server = create_server(
        _settings(tool_profile="admin", enable_sensitive_tools=True)
    )
    vm_volume_type = next(
        option
        for option in compute_server._tool_manager.get_tool("create_instance")
        .parameters["properties"]["volume_type"]["anyOf"]
        if option.get("type") == "string"
    )
    assert vm_volume_type["enum"] == properties["volume_type"]["enum"]


def test_volume_lifecycle_schemas_and_annotations_are_explicit() -> None:
    server = create_server(_settings(tool_profile="storage"))
    read_tools = {
        "list_volumes": {"vpc_krn", "region"},
        "list_volume_types": {"vpc_krn", "region"},
        "list_volume_snapshots": {"vpc_krn", "region"},
        "describe_volume_snapshot": {"snapshot_id", "vpc_krn", "region"},
        "list_volume_backups": {"vpc_krn", "region"},
        "describe_volume_backup": {"backup_id", "vpc_krn", "region"},
    }
    additive_tools = {
        "create_volume_snapshot_policy": {
            "name",
            "volume_id",
            "max_snapshots_allowed",
            "cron",
            "vpc_krn",
            "region",
            "confirm",
        },
        "create_volume_backup_policy": {
            "name",
            "volume_id",
            "max_backups_allowed",
            "cron",
            "vpc_krn",
            "region",
            "confirm",
        },
    }
    destructive_tools = {
        "update_volume_snapshot": {
            "snapshot_id",
            "vpc_krn",
            "region",
            "confirm",
        },
        "restore_volume_backup": {
            "backup_id",
            "name",
            "vpc_krn",
            "region",
            "confirm",
        },
        "delete_volume_snapshot_policy": {
            "volume_id",
            "vpc_krn",
            "region",
            "confirm",
        },
        "delete_volume_backup_policy": {
            "volume_id",
            "vpc_krn",
            "region",
            "confirm",
        },
        "extend_volume": {
            "volume_id",
            "new_size_gb",
            "vpc_krn",
            "region",
            "confirm",
        },
        "update_volume": {"volume_id", "vpc_krn", "region", "confirm"},
        "change_volume_type": {
            "volume_id",
            "volume_type",
            "vpc_krn",
            "region",
            "confirm",
        },
        "delete_volume_snapshot": {"snapshot_id", "vpc_krn", "region", "confirm"},
        "delete_volume_backup": {"backup_id", "vpc_krn", "region", "confirm"},
    }

    for tool_name, required in read_tools.items():
        tool = server._tool_manager.get_tool(tool_name)
        assert set(tool.parameters["required"]) == required
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.openWorldHint is True

    for tool_name, required in additive_tools.items():
        tool = server._tool_manager.get_tool(tool_name)
        assert set(tool.parameters["required"]) == required
        assert tool.annotations.readOnlyHint is False
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.idempotentHint is False
        assert tool.annotations.openWorldHint is True

    for tool_name, required in destructive_tools.items():
        tool = server._tool_manager.get_tool(tool_name)
        assert set(tool.parameters["required"]) == required
        assert tool.annotations.readOnlyHint is False
        assert tool.annotations.destructiveHint is True
        assert tool.annotations.idempotentHint is False
        assert tool.annotations.openWorldHint is True

    snapshot_properties = server._tool_manager.get_tool(
        "describe_volume_snapshot"
    ).parameters["properties"]
    backup_properties = server._tool_manager.get_tool(
        "describe_volume_backup"
    ).parameters["properties"]
    assert snapshot_properties["snapshot_id"]["pattern"].startswith("^krn:kbs:")
    assert snapshot_properties["vpc_krn"]["pattern"].startswith("^krn:vpc:")
    assert backup_properties["backup_id"]["minLength"] == 1
    assert backup_properties["backup_id"]["maxLength"] == 512
    assert backup_properties["vpc_krn"]["pattern"].startswith("^krn:vpc:")

    snapshot_policy = server._tool_manager.get_tool(
        "create_volume_snapshot_policy"
    ).parameters["properties"]
    backup_policy = server._tool_manager.get_tool(
        "create_volume_backup_policy"
    ).parameters["properties"]
    assert snapshot_policy["max_snapshots_allowed"]["minimum"] == 1
    assert backup_policy["max_backups_allowed"]["minimum"] == 1
    assert snapshot_policy["cron"]["minLength"] == 1
    assert snapshot_policy["cron"]["maxLength"] == 256

    restore = server._tool_manager.get_tool("restore_volume_backup").parameters[
        "properties"
    ]
    extend = server._tool_manager.get_tool("extend_volume").parameters["properties"]
    change_type = server._tool_manager.get_tool("change_volume_type").parameters[
        "properties"
    ]
    assert restore["allow_target_volume_overwrite"]["default"] is False
    assert extend["new_size_gb"]["minimum"] == 1
    assert extend["allow_attached_volume"]["default"] is False
    assert change_type["volume_type"]["enum"] == ["HNSS", "HNSS_Encrypted"]

    admin = create_server(_settings(tool_profile="admin"))
    force_delete = admin._tool_manager.get_tool("force_delete_volume")
    assert force_delete.parameters["properties"]["allow_attached_volume"]["default"] is False
    assert force_delete.annotations.readOnlyHint is False
    assert force_delete.annotations.destructiveHint is True
    assert force_delete.annotations.idempotentHint is False


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        (
            "update_volume_snapshot",
            {"snapshot_id": _SNAPSHOT_KRN, "name": "snapshot-renamed"},
        ),
        (
            "create_volume_snapshot_policy",
            {
                "name": "nightly-snapshots",
                "volume_id": _VOLUME_KRN,
                "max_snapshots_allowed": 7,
                "cron": "0 2 * * *",
            },
        ),
        ("delete_volume_snapshot_policy", {"volume_id": _VOLUME_KRN}),
        (
            "restore_volume_backup",
            {"backup_id": _BACKUP_ID, "name": "restored-volume"},
        ),
        (
            "create_volume_backup_policy",
            {
                "name": "weekly-backups",
                "volume_id": _VOLUME_KRN,
                "max_backups_allowed": 4,
                "cron": "0 3 * * 0",
            },
        ),
        ("delete_volume_backup_policy", {"volume_id": _VOLUME_KRN}),
        ("extend_volume", {"volume_id": _VOLUME_KRN, "new_size_gb": 200}),
        ("update_volume", {"volume_id": _VOLUME_KRN, "name": "volume-renamed"}),
        (
            "change_volume_type",
            {"volume_id": _VOLUME_KRN, "volume_type": "HNSS_Encrypted"},
        ),
        ("force_delete_volume", {"volume_id": _VOLUME_KRN}),
    ],
)
def test_selected_kbs_mutation_guards_run_before_client_initialization(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    arguments: dict[str, object],
) -> None:
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)
    common = {
        "vpc_krn": _VPC_KRN,
        "region": "In-Bangalore-1",
    }

    for read_only, confirm, error in (
        (False, False, "confirm=true"),
        (True, True, "READ_ONLY"),
    ):
        server = create_server(_settings(tool_profile="admin", read_only=read_only))
        with pytest.raises(ToolError, match=error):
            server._tool_manager.get_tool(tool_name).fn(
                **common,
                **arguments,
                confirm=confirm,
            )

    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        (
            "list_volumes",
            {"vpc_krn": "not-a-vpc-krn", "region": "In-Bangalore-1"},
        ),
        (
            "list_volume_snapshots",
            {"vpc_krn": _VPC_KRN, "region": "In-Hyderabad-1"},
        ),
        (
            "describe_volume_snapshot",
            {
                "snapshot_id": "not-a-snapshot-krn",
                "vpc_krn": _VPC_KRN,
                "region": "In-Bangalore-1",
            },
        ),
        (
            "list_volume_backups",
            {"vpc_krn": "not-a-vpc-krn", "region": "In-Bangalore-1"},
        ),
        (
            "describe_volume_backup",
            {
                "backup_id": "unsafe/backup-id",
                "vpc_krn": _VPC_KRN,
                "region": "In-Bangalore-1",
            },
        ),
        (
            "delete_volume_snapshot",
            {
                "snapshot_id": _SNAPSHOT_KRN.replace(
                    "customer-test", "other-customer"
                ),
                "vpc_krn": _VPC_KRN,
                "region": "In-Bangalore-1",
                "confirm": True,
            },
        ),
        (
            "delete_volume_backup",
            {
                "backup_id": "unsafe/backup-id",
                "vpc_krn": _VPC_KRN,
                "region": "In-Bangalore-1",
                "confirm": True,
            },
        ),
    ],
)
def test_invalid_volume_lifecycle_inputs_never_initialize_client(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    arguments: dict[str, object],
) -> None:
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError):
        server._tool_manager.get_tool(tool_name).fn(**arguments)
    get_client.assert_not_called()


def test_list_volume_types_tool_forwards_only_explicit_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    adapter = MagicMock(return_value={"volume_types": ["HNSS", "HNSS_Encrypted"]})
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "list_kbs_volume_types", adapter)

    result = server._tool_manager.get_tool("list_volume_types").fn(
        vpc_krn=_VPC_KRN,
        region="In-Bangalore-1",
    )

    assert result.ok is True
    adapter.assert_called_once_with(
        client,
        vpc_krn=_VPC_KRN,
        x_region="In-Bangalore-1",
    )


def test_update_volume_snapshot_preflights_exact_id_and_forwards_supplied_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    retrieve = MagicMock(return_value={"id": _SNAPSHOT_KRN})
    update = MagicMock(return_value={"status_code": 200})
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "retrieve_kbs_volume_snapshot", retrieve)
    monkeypatch.setattr(storage_mod, "update_kbs_volume_snapshot", update)

    result = server._tool_manager.get_tool("update_volume_snapshot").fn(
        snapshot_id=_SNAPSHOT_KRN,
        vpc_krn=_VPC_KRN,
        description="retained snapshot",
        metadata={"environment": "test"},
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    retrieve.assert_called_once_with(
        client,
        snapshot_id=_SNAPSHOT_KRN,
        vpc_krn=_VPC_KRN,
        x_region="In-Bangalore-1",
    )
    update.assert_called_once_with(
        client,
        snapshot_id=_SNAPSHOT_KRN,
        vpc_krn=_VPC_KRN,
        x_region="In-Bangalore-1",
        name=None,
        description="retained snapshot",
        metadata={"environment": "test"},
    )


@pytest.mark.parametrize(
    ("tool_name", "adapter_name", "arguments", "expected_arguments"),
    [
        (
            "create_volume_snapshot_policy",
            "create_kbs_volume_snapshot_policy",
            {
                "name": "nightly-snapshots",
                "max_snapshots_allowed": 7,
                "cron": "0 2 * * *",
            },
            {
                "name": "nightly-snapshots",
                "max_snapshots_allowed": 7,
                "cron": "0 2 * * *",
            },
        ),
        (
            "delete_volume_snapshot_policy",
            "delete_kbs_volume_snapshot_policy",
            {},
            {},
        ),
        (
            "create_volume_backup_policy",
            "create_kbs_volume_backup_policy",
            {
                "name": "weekly-backups",
                "max_backups_allowed": 4,
                "cron": "0 3 * * 0",
            },
            {
                "name": "weekly-backups",
                "max_backups_allowed": 4,
                "cron": "0 3 * * 0",
            },
        ),
        (
            "delete_volume_backup_policy",
            "delete_kbs_volume_backup_policy",
            {},
            {},
        ),
    ],
)
def test_volume_policy_tools_preflight_exact_volume_then_call_adapter(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    adapter_name: str,
    arguments: dict[str, object],
    expected_arguments: dict[str, object],
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        "attachments": [],
    }
    adapter = MagicMock(return_value={"status_code": 202})
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, adapter_name, adapter)

    result = server._tool_manager.get_tool(tool_name).fn(
        volume_id=_VOLUME_KRN,
        vpc_krn=_VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
        **arguments,
    )

    assert result.ok is True
    client.kbs.retrieve_volume.assert_called_once_with(
        _VOLUME_KRN,
        k_tenant_id=_VPC_KRN,
        x_region="In-Bangalore-1",
    )
    adapter.assert_called_once_with(
        client,
        volume_id=_VOLUME_KRN,
        vpc_krn=_VPC_KRN,
        x_region="In-Bangalore-1",
        **expected_arguments,
    )


def test_restore_volume_backup_without_target_preflights_exact_backup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    retrieve = MagicMock(return_value={"id": _BACKUP_ID})
    restore = MagicMock(return_value={"status_code": 202})
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "retrieve_kbs_volume_backup", retrieve)
    monkeypatch.setattr(storage_mod, "restore_kbs_volume_backup", restore)

    result = server._tool_manager.get_tool("restore_volume_backup").fn(
        backup_id=_BACKUP_ID,
        name="restored-volume",
        vpc_krn=_VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    retrieve.assert_called_once_with(
        client,
        backup_id=_BACKUP_ID,
        vpc_krn=_VPC_KRN,
        x_region="In-Bangalore-1",
    )
    restore.assert_called_once_with(
        client,
        backup_id=_BACKUP_ID,
        name="restored-volume",
        vpc_krn=_VPC_KRN,
        x_region="In-Bangalore-1",
        target_volume_id=None,
    )


def test_restore_volume_backup_target_requires_opt_in_before_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod

    server = create_server(_settings(tool_profile="storage"))
    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match="allow_target_volume_overwrite=true"):
        server._tool_manager.get_tool("restore_volume_backup").fn(
            backup_id=_BACKUP_ID,
            name="restored-volume",
            target_volume_id=_VOLUME_KRN,
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

    get_client.assert_not_called()


def test_restore_volume_backup_target_must_be_detached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        "attachments": [{"instance_id": "vm-1"}],
    }
    retrieve = MagicMock(return_value={"id": _BACKUP_ID})
    restore = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "retrieve_kbs_volume_backup", retrieve)
    monkeypatch.setattr(storage_mod, "restore_kbs_volume_backup", restore)

    with pytest.raises(ToolError, match="requires a detached volume"):
        server._tool_manager.get_tool("restore_volume_backup").fn(
            backup_id=_BACKUP_ID,
            name="restored-volume",
            target_volume_id=_VOLUME_KRN,
            allow_target_volume_overwrite=True,
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

    restore.assert_not_called()


@pytest.mark.parametrize(
    ("tool_name", "adapter_name", "volume", "arguments", "expected_arguments"),
    [
        (
            "update_volume",
            "update_kbs_volume",
            {"id": _VOLUME_KRN, "attachments": []},
            {"description": "application data", "metadata": {"owner": "platform"}},
            {
                "name": None,
                "description": "application data",
                "metadata": {"owner": "platform"},
            },
        ),
        (
            "extend_volume",
            "extend_kbs_volume",
            {"id": _VOLUME_KRN, "attachments": [], "size": 50},
            {"new_size_gb": 200},
            {"new_size_gb": 200},
        ),
        (
            "change_volume_type",
            "change_kbs_volume_type",
            {"id": _VOLUME_KRN, "attachments": [], "volume_type": "HNSS"},
            {"volume_type": "HNSS_Encrypted"},
            {"volume_type": "HNSS_Encrypted"},
        ),
        (
            "force_delete_volume",
            "force_delete_kbs_volume",
            {"id": _VOLUME_KRN, "status": "error", "attachments": []},
            {},
            {},
        ),
    ],
)
def test_selected_volume_mutations_preflight_then_call_exact_adapter(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    adapter_name: str,
    volume: dict[str, object],
    arguments: dict[str, object],
    expected_arguments: dict[str, object],
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="admin"))
    client = MagicMock()
    client.kbs.retrieve_volume.return_value = volume
    adapter = MagicMock(return_value={"status_code": 202})
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, adapter_name, adapter)

    result = server._tool_manager.get_tool(tool_name).fn(
        volume_id=_VOLUME_KRN,
        vpc_krn=_VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
        **arguments,
    )

    assert result.ok is True
    client.kbs.retrieve_volume.assert_called_once_with(
        _VOLUME_KRN,
        k_tenant_id=_VPC_KRN,
        x_region="In-Bangalore-1",
    )
    adapter.assert_called_once_with(
        client,
        volume_id=_VOLUME_KRN,
        vpc_krn=_VPC_KRN,
        x_region="In-Bangalore-1",
        **expected_arguments,
    )


def test_extend_volume_requires_growth_and_attached_volume_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    adapter = MagicMock(return_value={"status_code": 202})
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "extend_kbs_volume", adapter)

    client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        "attachments": [],
        "size": 50,
    }
    with pytest.raises(ToolError, match="must be greater than current size"):
        server._tool_manager.get_tool("extend_volume").fn(
            volume_id=_VOLUME_KRN,
            new_size_gb=50,
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

    client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        "attachments": [{"instance_id": "vm-1"}],
        "size": 50,
    }
    with pytest.raises(ToolError, match="allow_attached_volume=true"):
        server._tool_manager.get_tool("extend_volume").fn(
            volume_id=_VOLUME_KRN,
            new_size_gb=100,
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

    result = server._tool_manager.get_tool("extend_volume").fn(
        volume_id=_VOLUME_KRN,
        new_size_gb=100,
        vpc_krn=_VPC_KRN,
        allow_attached_volume=True,
        region="In-Bangalore-1",
        confirm=True,
    )
    assert result.ok is True
    adapter.assert_called_once()


def test_change_volume_type_requires_detached_volume_and_actual_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    adapter = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "change_kbs_volume_type", adapter)

    client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        "attachments": [{"instance_id": "vm-1"}],
        "volume_type": "HNSS",
    }
    with pytest.raises(ToolError, match="requires a detached volume"):
        server._tool_manager.get_tool("change_volume_type").fn(
            volume_id=_VOLUME_KRN,
            volume_type="HNSS_Encrypted",
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

    client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        "attachments": [],
        "volume_type": "HNSS_Encrypted",
    }
    with pytest.raises(ToolError, match="already has the requested volume_type"):
        server._tool_manager.get_tool("change_volume_type").fn(
            volume_id=_VOLUME_KRN,
            volume_type="HNSS_Encrypted",
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

    adapter.assert_not_called()


def test_force_delete_volume_requires_attached_volume_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="admin"))
    client = MagicMock()
    client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        "status": "failed",
        "attachments": [{"instance_id": "vm-1"}],
    }
    adapter = MagicMock(return_value={"status_code": 204, "completed": True})
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "force_delete_kbs_volume", adapter)

    with pytest.raises(ToolError, match="allow_attached_volume=true"):
        server._tool_manager.get_tool("force_delete_volume").fn(
            volume_id=_VOLUME_KRN,
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )
    adapter.assert_not_called()

    result = server._tool_manager.get_tool("force_delete_volume").fn(
        volume_id=_VOLUME_KRN,
        vpc_krn=_VPC_KRN,
        allow_attached_volume=True,
        region="In-Bangalore-1",
        confirm=True,
    )
    assert result.ok is True
    adapter.assert_called_once()


@pytest.mark.parametrize(
    "volume",
    [
        {"id": _VOLUME_KRN, "status": "available", "attachments": []},
        {"id": _VOLUME_KRN, "status": "deleting", "attachments": []},
        {"id": _VOLUME_KRN, "attachments": []},
    ],
)
def test_force_delete_volume_blocks_non_failed_or_unverifiable_status(
    monkeypatch: pytest.MonkeyPatch,
    volume: dict[str, object],
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="admin"))
    client = MagicMock()
    client.kbs.retrieve_volume.return_value = volume
    adapter = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "force_delete_kbs_volume", adapter)

    with pytest.raises(ToolError, match="failed volume status"):
        server._tool_manager.get_tool("force_delete_volume").fn(
            volume_id=_VOLUME_KRN,
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )

    adapter.assert_not_called()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "ERROR"),
        ("status", "error_deleting"),
        ("status", "failed"),
        ("state", "failure"),
    ],
)
def test_force_delete_volume_accepts_explicit_failed_statuses(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="admin"))
    client = MagicMock()
    client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        field: value,
        "attachments": [],
    }
    adapter = MagicMock(return_value={"status_code": 204, "completed": True})
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "force_delete_kbs_volume", adapter)

    result = server._tool_manager.get_tool("force_delete_volume").fn(
        volume_id=_VOLUME_KRN,
        vpc_krn=_VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    adapter.assert_called_once()


def test_create_volume_uses_validated_current_adapter_and_safe_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    create_adapter = MagicMock(
        return_value={"status_code": 202, "accepted": True, "completed": False}
    )
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "create_kbs_volume", create_adapter)

    result = server._tool_manager.get_tool("create_volume").fn(
        name="volume-20260711",
        size_gb=50,
        vpc_krn=_VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    create_adapter.assert_called_once_with(
        client,
        name="volume-20260711",
        size_gb=50,
        vpc_krn=_VPC_KRN,
        x_region="In-Bangalore-1",
        volume_type="HNSS",
        multiattach=False,
        description=None,
        source_type=None,
        source_id=None,
    )


@pytest.mark.parametrize(
    ("source_type", "source_id"),
    [
        ("image", _IMAGE_KRN),
        ("volume", _VOLUME_KRN),
        ("snapshot", _SNAPSHOT_KRN),
    ],
)
def test_create_volume_forwards_validated_typed_source(
    monkeypatch: pytest.MonkeyPatch,
    source_type: str,
    source_id: str,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    create_adapter = MagicMock(
        return_value={"status_code": 202, "accepted": True, "completed": False}
    )
    if source_type == "volume":
        client.kbs.retrieve_volume.return_value = {"id": source_id}
    elif source_type == "snapshot":
        request = httpx.Request("GET", "https://cloud.olakrutrim.com/kbs/v1/snapshots")
        client.get.return_value = httpx.Response(
            200,
            json={"id": source_id},
            request=request,
        )
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "create_kbs_volume", create_adapter)

    result = server._tool_manager.get_tool("create_volume").fn(
        name="source-backed-20260714",
        size_gb=50,
        vpc_krn=_VPC_KRN,
        source_type=source_type,
        source_id=source_id,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    create_adapter.assert_called_once_with(
        client,
        name="source-backed-20260714",
        size_gb=50,
        vpc_krn=_VPC_KRN,
        x_region="In-Bangalore-1",
        volume_type="HNSS",
        multiattach=False,
        description=None,
        source_type=source_type,
        source_id=source_id,
    )
    if source_type == "volume":
        client.kbs.retrieve_volume.assert_called_once_with(
            source_id,
            k_tenant_id=_VPC_KRN,
            x_region="In-Bangalore-1",
        )
    elif source_type == "snapshot":
        _, kwargs = client.get.call_args
        assert kwargs["options"]["headers"]["K-Tenant-ID"] == _VPC_KRN


@pytest.mark.parametrize(
    ("source_type", "source_id", "different_source_id"),
    [
        (
            "volume",
            _VOLUME_KRN,
            _VOLUME_KRN.replace("000000000001", "000000000009"),
        ),
        (
            "snapshot",
            _SNAPSHOT_KRN,
            _SNAPSHOT_KRN.replace("000000000003", "000000000009"),
        ),
    ],
)
def test_create_volume_source_preflight_blocks_mismatched_identity(
    monkeypatch: pytest.MonkeyPatch,
    source_type: str,
    source_id: str,
    different_source_id: str,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    create_adapter = MagicMock()
    if source_type == "volume":
        client.kbs.retrieve_volume.return_value = {"id": different_source_id}
    else:
        request = httpx.Request("GET", "https://cloud.olakrutrim.com/kbs/v1/snapshots")
        client.get.return_value = httpx.Response(
            200,
            json={"id": different_source_id},
            request=request,
        )
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    monkeypatch.setattr(storage_mod, "create_kbs_volume", create_adapter)

    with pytest.raises(ToolError, match="did not return the requested"):
        server._tool_manager.get_tool("create_volume").fn(
            name="source-backed-20260714",
            size_gb=50,
            vpc_krn=_VPC_KRN,
            source_type=source_type,
            source_id=source_id,
            region="In-Bangalore-1",
            confirm=True,
        )

    create_adapter.assert_not_called()


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"size_gb": 0}, "positive integer"),
        ({"volume_type": "ssd"}, "HNSS.*HNSS_Encrypted"),
        ({"vpc_krn": "tenant-uuid"}, "full source VPC KRN"),
        ({"source_type": "image"}, "source_type and source_id must be provided together"),
        ({"source_id": _IMAGE_KRN}, "source_type and source_id must be provided together"),
        (
            {"source_type": "image", "source_id": "image-uuid"},
            "full Krutrim machine-image KRN",
        ),
        (
            {
                "source_type": "image",
                "source_id": _IMAGE_KRN.replace(
                    "In-Bangalore-1", "In-Hyderabad-1"
                ),
            },
            "image_krn region.*does not match selected region",
        ),
        (
            {
                "source_type": "volume",
                "source_id": _VOLUME_KRN.replace("customer-test", "other-customer"),
            },
            "scope does not match vpc_krn",
        ),
        (
            {"source_type": "snapshot", "source_id": _VOLUME_KRN},
            "snapshot_id must be a full Krutrim KBS KRN",
        ),
        (
            {"region": "In-Hyderabad-1"},
            "vpc_krn region.*does not match selected region",
        ),
    ],
)
def test_invalid_create_volume_inputs_never_initialize_client(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    error: str,
) -> None:
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)
    arguments: dict[str, object] = {
        "name": "volume-20260711",
        "size_gb": 50,
        "vpc_krn": _VPC_KRN,
        "region": "In-Bangalore-1",
        "confirm": True,
    }
    arguments.update(overrides)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("create_volume").fn(**arguments)
    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("settings_overrides", "confirm", "error"),
    [
        ({}, False, "confirm=true"),
        ({"read_only": True}, True, "READ_ONLY"),
    ],
)
def test_create_volume_guards_run_before_client_initialization(
    monkeypatch: pytest.MonkeyPatch,
    settings_overrides: dict[str, object],
    confirm: bool,
    error: str,
) -> None:
    server = create_server(_settings(tool_profile="storage", **settings_overrides))
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("create_volume").fn(
            name="volume-20260711",
            size_gb=50,
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=confirm,
        )
    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("tool_name", "identifier_name", "identifier"),
    [
        ("delete_volume_snapshot", "snapshot_id", _SNAPSHOT_KRN),
        ("delete_volume_backup", "backup_id", _BACKUP_ID),
    ],
)
def test_volume_lifecycle_deletes_require_confirmation_before_client(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    identifier_name: str,
    identifier: str,
) -> None:
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)
    arguments = {
        identifier_name: identifier,
        "vpc_krn": _VPC_KRN,
        "region": "In-Bangalore-1",
        "confirm": False,
    }

    with pytest.raises(ToolError, match="confirm=true"):
        server._tool_manager.get_tool(tool_name).fn(**arguments)
    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("tool_name", "identifier_name", "identifier"),
    [
        ("delete_volume_snapshot", "snapshot_id", _SNAPSHOT_KRN),
        ("delete_volume_backup", "backup_id", _BACKUP_ID),
    ],
)
def test_read_only_blocks_volume_lifecycle_deletes_before_client(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    identifier_name: str,
    identifier: str,
) -> None:
    server = create_server(_settings(tool_profile="storage", read_only=True))
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)
    arguments = {
        identifier_name: identifier,
        "vpc_krn": _VPC_KRN,
        "region": "In-Bangalore-1",
        "confirm": True,
    }

    with pytest.raises(ToolError, match="READ_ONLY"):
        server._tool_manager.get_tool(tool_name).fn(**arguments)
    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("tool_name", "identifier_name", "identifier", "retrieve_name", "delete_name"),
    [
        (
            "delete_volume_snapshot",
            "snapshot_id",
            _SNAPSHOT_KRN,
            "retrieve_kbs_volume_snapshot",
            "delete_kbs_volume_snapshot",
        ),
        (
            "delete_volume_backup",
            "backup_id",
            _BACKUP_ID,
            "retrieve_kbs_volume_backup",
            "delete_kbs_volume_backup",
        ),
    ],
)
def test_volume_lifecycle_delete_preflights_exact_id_then_deletes_once(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    identifier_name: str,
    identifier: str,
    retrieve_name: str,
    delete_name: str,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    calls: list[str] = []
    retrieve = MagicMock(
        side_effect=lambda *args, **kwargs: calls.append("retrieve")
        or {"id": identifier}
    )
    delete = MagicMock(
        side_effect=lambda *args, **kwargs: calls.append("delete")
        or {"completed": True}
    )
    monkeypatch.setattr(storage_mod, retrieve_name, retrieve)
    monkeypatch.setattr(storage_mod, delete_name, delete)

    result = server._tool_manager.get_tool(tool_name).fn(
        **{
            identifier_name: identifier,
            "vpc_krn": _VPC_KRN,
            "region": "In-Bangalore-1",
            "confirm": True,
        }
    )

    assert result.ok is True
    assert calls == ["retrieve", "delete"]
    retrieve.assert_called_once_with(
        client,
        **{
            identifier_name: identifier,
            "vpc_krn": _VPC_KRN,
            "x_region": "In-Bangalore-1",
        },
    )
    delete.assert_called_once_with(
        client,
        **{
            identifier_name: identifier,
            "vpc_krn": _VPC_KRN,
            "x_region": "In-Bangalore-1",
        },
    )


@pytest.mark.parametrize(
    ("tool_name", "identifier_name", "identifier", "retrieve_name", "delete_name"),
    [
        (
            "delete_volume_snapshot",
            "snapshot_id",
            _SNAPSHOT_KRN,
            "retrieve_kbs_volume_snapshot",
            "delete_kbs_volume_snapshot",
        ),
        (
            "delete_volume_backup",
            "backup_id",
            _BACKUP_ID,
            "retrieve_kbs_volume_backup",
            "delete_kbs_volume_backup",
        ),
    ],
)
def test_volume_lifecycle_delete_blocks_mismatched_preflight_id(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    identifier_name: str,
    identifier: str,
    retrieve_name: str,
    delete_name: str,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    retrieve = MagicMock(return_value={"id": f"{identifier}-different"})
    delete = MagicMock()
    monkeypatch.setattr(storage_mod, retrieve_name, retrieve)
    monkeypatch.setattr(storage_mod, delete_name, delete)

    with pytest.raises(ToolError, match="did not return the requested id"):
        server._tool_manager.get_tool(tool_name).fn(
            **{
                identifier_name: identifier,
                "vpc_krn": _VPC_KRN,
                "region": "In-Bangalore-1",
                "confirm": True,
            }
        )
    retrieve.assert_called_once()
    delete.assert_not_called()


def test_backup_delete_leaves_primary_and_dependency_policy_to_kbs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from krutrim_mcp_server import client as client_mod
    from krutrim_mcp_server.tools.storage import storage as storage_mod

    server = create_server(_settings(tool_profile="storage"))
    client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: client)
    retrieve = MagicMock(
        return_value={
            "id": _BACKUP_ID,
            "incremental": False,
            "has_dependent_backups": True,
        }
    )
    delete = MagicMock(return_value={"completed": True})
    monkeypatch.setattr(storage_mod, "retrieve_kbs_volume_backup", retrieve)
    monkeypatch.setattr(storage_mod, "delete_kbs_volume_backup", delete)

    result = server._tool_manager.get_tool("delete_volume_backup").fn(
        backup_id=_BACKUP_ID,
        vpc_krn=_VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    delete.assert_called_once()


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"name": "bad--name"}, "adjacent dots or hyphens"),
        ({"volume_id": "not-a-volume-krn"}, "full Krutrim block-volume KRN"),
        (
            {"volume_id": _VOLUME_KRN.replace("customer-test", "other-customer")},
            "scope does not match vpc_krn",
        ),
        ({"vpc_krn": "not-a-vpc-krn"}, "full source VPC KRN"),
        (
            {"region": "In-Hyderabad-1"},
            "vpc_krn region.*does not match selected region",
        ),
    ],
)
def test_invalid_copy_inputs_make_no_preflight_or_create_request(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    error: str,
) -> None:
    mock_client = MagicMock()
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock(return_value=mock_client)
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)
    arguments: dict[str, object] = {
        "name": "snapshot-20260711",
        "volume_id": _VOLUME_KRN,
        "vpc_krn": _VPC_KRN,
        "region": "In-Bangalore-1",
        "confirm": True,
    }
    arguments.update(overrides)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("create_volume_snapshot").fn(**arguments)
    get_client.assert_not_called()
    mock_client.kbs.retrieve_volume.assert_not_called()
    mock_client.post.assert_not_called()


@pytest.mark.parametrize("tool_name", ["create_volume_snapshot", "create_volume_backup"])
def test_snapshot_and_backup_require_confirmation_before_preflight(
    monkeypatch: pytest.MonkeyPatch, tool_name: str
) -> None:
    mock_client = MagicMock()
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    arguments: dict[str, object] = {
        "name": "copy-20260711",
        "volume_id": _VOLUME_KRN,
        "vpc_krn": _VPC_KRN,
        "region": "In-Bangalore-1",
        "confirm": False,
    }
    with pytest.raises(ToolError, match="confirm=true"):
        server._tool_manager.get_tool(tool_name).fn(**arguments)
    mock_client.kbs.retrieve_volume.assert_not_called()
    mock_client.post.assert_not_called()


@pytest.mark.parametrize("tool_name", ["create_volume_snapshot", "create_volume_backup"])
def test_read_only_blocks_snapshot_and_backup_before_preflight(
    monkeypatch: pytest.MonkeyPatch, tool_name: str
) -> None:
    mock_client = MagicMock()
    server = create_server(_settings(tool_profile="storage", read_only=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    arguments: dict[str, object] = {
        "name": "copy-20260711",
        "volume_id": _VOLUME_KRN,
        "vpc_krn": _VPC_KRN,
        "region": "In-Bangalore-1",
        "confirm": True,
    }
    with pytest.raises(ToolError, match="READ_ONLY"):
        server._tool_manager.get_tool(tool_name).fn(**arguments)
    mock_client.kbs.retrieve_volume.assert_not_called()
    mock_client.post.assert_not_called()


def test_attached_volume_copy_requires_opt_in_and_sets_force_only_after_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        "status": "in-use",
        "attachments": [{"instance_id": "vm-1"}],
    }
    mock_client.post.return_value = httpx.Response(
        202, json={"id": "snapshot-1", "status": "creating"}
    )
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    tool = server._tool_manager.get_tool("create_volume_snapshot")
    arguments = {
        "name": "snapshot-20260711",
        "volume_id": _VOLUME_KRN,
        "vpc_krn": _VPC_KRN,
        "region": "In-Bangalore-1",
        "confirm": True,
    }

    with pytest.raises(ToolError, match="allow_attached_volume=true"):
        tool.fn(**arguments)
    mock_client.post.assert_not_called()

    result = tool.fn(**arguments, allow_attached_volume=True)
    assert result.ok is True
    mock_client.kbs.retrieve_volume.assert_called_with(
        _VOLUME_KRN,
        k_tenant_id=_VPC_KRN,
        x_region="In-Bangalore-1",
    )
    _, kwargs = mock_client.post.call_args
    assert kwargs["body"] == {
        "name": "snapshot-20260711",
        "description": "",
        "volume_id": _VOLUME_KRN,
        "force": True,
    }
    assert kwargs["options"] == {
        "headers": {
            "K-Tenant-ID": _VPC_KRN,
            "x-region": "In-Bangalore-1",
        }
    }


def test_backup_is_primary_only_after_detached_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.kbs.retrieve_volume.return_value = VolumeDetail(
        id=_VOLUME_KRN.rsplit(":", 1)[-1],
        krn=_VOLUME_KRN,
        status="success",
        attachments=[],
    )
    mock_client.post.return_value = httpx.Response(
        202, json={"id": "backup-1", "status": "creating"}
    )
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    result = server._tool_manager.get_tool("create_volume_backup").fn(
        name="primary-20260711",
        volume_id=_VOLUME_KRN,
        vpc_krn=_VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    _, kwargs = mock_client.post.call_args
    assert kwargs["body"]["volume_id"] == _VOLUME_KRN
    assert kwargs["body"]["incremental"] is False
    assert kwargs["body"]["force"] is False


def test_copy_preflight_blocks_a_mismatched_source_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.kbs.retrieve_volume.return_value = VolumeDetail(
        id=_VOLUME_KRN.replace("000000000001", "000000000099"),
        status="success",
        attachments=[],
    )
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    with pytest.raises(ToolError, match="did not return the requested volume KRN"):
        server._tool_manager.get_tool("create_volume_snapshot").fn(
            name="snapshot-20260711",
            volume_id=_VOLUME_KRN,
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )
    mock_client.post.assert_not_called()


def test_copy_preflight_accepts_verified_available_fixture_without_attachments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.kbs.retrieve_volume.return_value = VolumeDetail(
        id=_VOLUME_KRN,
        status="success",
        state="available",  # type: ignore[call-arg]
    )
    mock_client.post.return_value = httpx.Response(
        202, json={"id": "snapshot-1", "status": "creating"}
    )
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    result = server._tool_manager.get_tool("create_volume_snapshot").fn(
        name="snapshot-20260711",
        volume_id=_VOLUME_KRN,
        vpc_krn=_VPC_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    _, kwargs = mock_client.post.call_args
    assert kwargs["body"]["volume_id"] == _VOLUME_KRN
    assert kwargs["body"]["force"] is False


def test_copy_preflight_fails_closed_when_attachment_state_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.kbs.retrieve_volume.return_value = {
        "id": _VOLUME_KRN,
        "status": "success",
    }
    server = create_server(_settings(tool_profile="storage"))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    with pytest.raises(ToolError, match="could not verify volume attachment state"):
        server._tool_manager.get_tool("create_volume_snapshot").fn(
            name="snapshot-20260711",
            volume_id=_VOLUME_KRN,
            vpc_krn=_VPC_KRN,
            region="In-Bangalore-1",
            confirm=True,
        )
    mock_client.post.assert_not_called()


def test_unclassified_new_tool_fails_registration() -> None:
    server = GuardedFastMCP("test")
    with pytest.raises(ValueError, match="no explicit production safety policy"):

        @server.tool()
        def accidental_mutation() -> str:
            return "unsafe"


def test_resource_lifecycle_defaults_are_conservative() -> None:
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    create_instance = server._tool_manager.get_tool("create_instance").parameters["properties"]
    delete_instance = server._tool_manager.get_tool("delete_instance").parameters["properties"]

    assert create_instance["delete_on_termination"]["default"] is False
    assert create_instance["volume_size"]["default"] is None
    assert create_instance["volume_type"]["default"] is None
    assert delete_instance["delete_volume"]["default"] is False


def test_existing_volume_schema_is_one_full_boot_volume_krn() -> None:
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    properties = server._tool_manager.get_tool("create_instance").parameters["properties"]

    volume_array = next(
        option
        for option in properties["existing_volume_ids"]["anyOf"]
        if option.get("type") == "array"
    )
    volume_type = next(
        option
        for option in properties["volume_type"]["anyOf"]
        if option.get("type") == "string"
    )

    assert volume_array["minItems"] == 1
    assert volume_array["maxItems"] == 1
    assert volume_array["items"]["minLength"] == 1
    assert "boot-volume KRN" in volume_array["description"]
    assert volume_type["enum"] == ["HNSS", "HNSS_Encrypted"]


def test_create_instance_reuses_existing_boot_volume_without_new_volume_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.create_instance.return_value = {"instanceKrn": "vm-1"}
    _configure_compute_flavor_catalog(mock_client)
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    result = server._tool_manager.get_tool("create_instance").fn(
        instance_name="vm-from-volume",
        instance_type="CPU-2x-8GB",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        ssh_key_name="ssh-key-1",
        security_group_ids=["sg-1"],
        existing_volume_ids=[_VOLUME_KRN],
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    kwargs = mock_client.highlvlvpc.create_instance.call_args.kwargs
    assert kwargs["volumes"] == [_VOLUME_KRN]
    assert kwargs["delete_on_termination"] is False
    assert not {"image_krn", "volume_name", "volume_size", "volumetype"} & kwargs.keys()


def test_create_instance_new_volume_uses_supported_safe_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.create_instance.return_value = {"instanceKrn": "vm-1"}
    _configure_compute_flavor_catalog(mock_client)
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    result = server._tool_manager.get_tool("create_instance").fn(
        instance_name="vm-new-volume",
        instance_type="CPU-2x-8GB",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        ssh_key_name="ssh-key-1",
        security_group_ids=["sg-1"],
        image_krn="image-1",
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    kwargs = mock_client.highlvlvpc.create_instance.call_args.kwargs
    assert kwargs["image_krn"] == "image-1"
    assert kwargs["volume_name"] == "vm-new-volume-volume"
    assert kwargs["volume_size"] == 50
    assert kwargs["volumetype"] == "HNSS"
    assert "volumes" not in kwargs


def test_create_instance_forwards_explicit_encrypted_volume_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.create_instance.return_value = {"instanceKrn": "vm-1"}
    _configure_compute_flavor_catalog(mock_client)
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    result = server._tool_manager.get_tool("create_instance").fn(
        instance_name="vm-encrypted-volume",
        instance_type="CPU-2x-8GB",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        ssh_key_name="ssh-key-1",
        security_group_ids=["sg-1"],
        image_krn="image-1",
        volume_type="HNSS_Encrypted",
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    assert (
        mock_client.highlvlvpc.create_instance.call_args.kwargs["volumetype"]
        == "HNSS_Encrypted"
    )


def test_create_instance_rejects_unsupported_volume_type_before_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    get_client = MagicMock()
    monkeypatch.setattr(client_mod.get_session(), "get_client", get_client)

    with pytest.raises(ToolError, match="HNSS.*HNSS_Encrypted"):
        server._tool_manager.get_tool("create_instance").fn(
            instance_name="vm-invalid-volume",
            instance_type="CPU-2x-8GB",
            vpc_id="vpc-1",
            subnet_id="subnet-1",
            ssh_key_name="ssh-key-1",
            security_group_ids=["sg-1"],
            image_krn="image-1",
            volume_type="ssd",
            region="In-Bangalore-1",
            confirm=True,
        )
    get_client.assert_not_called()


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"existing_volume_ids": []}, "exactly one existing boot-volume KRN"),
        ({"existing_volume_ids": ["volume-uuid"]}, "full Krutrim block-volume KRN"),
        (
            {
                "existing_volume_ids": [
                    _VOLUME_KRN.replace("In-Bangalore-1", "In-Hyderabad-1")
                ]
            },
            "does not match selected region",
        ),
        (
            {
                "existing_volume_ids": [
                    _VOLUME_KRN,
                    _VOLUME_KRN.replace("000000000001", "000000000002"),
                ]
            },
            "exactly one existing boot-volume KRN",
        ),
        (
            {"existing_volume_ids": [_VOLUME_KRN], "image_krn": "image-1"},
            "cannot be combined with new-volume fields: image_krn",
        ),
        (
            {"existing_volume_ids": [_VOLUME_KRN], "volume_name": "new-volume"},
            "cannot be combined with new-volume fields: volume_name",
        ),
        (
            {"existing_volume_ids": [_VOLUME_KRN], "volume_size": 50},
            "cannot be combined with new-volume fields: volume_size",
        ),
        (
            {"existing_volume_ids": [_VOLUME_KRN], "volume_type": "HNSS"},
            "cannot be combined with new-volume fields: volume_type",
        ),
        (
            {"existing_volume_ids": [_VOLUME_KRN], "delete_on_termination": True},
            "delete_on_termination must be false",
        ),
        ({}, "image_krn is required when creating a new boot volume"),
    ],
)
def test_create_instance_rejects_ambiguous_or_unsafe_volume_inputs(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    error: str,
) -> None:
    mock_client = MagicMock()
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    arguments: dict[str, object] = {
        "instance_name": "vm-1",
        "instance_type": "CPU-2x-8GB",
        "vpc_id": "vpc-1",
        "subnet_id": "subnet-1",
        "ssh_key_name": "ssh-key-1",
        "security_group_ids": ["sg-1"],
        "region": "In-Bangalore-1",
        "confirm": True,
    }
    arguments.update(overrides)

    with pytest.raises(ToolError, match=error):
        server._tool_manager.get_tool("create_instance").fn(**arguments)
    mock_client.highlvlvpc.create_instance.assert_not_called()


def test_create_instance_existing_volume_still_requires_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    with pytest.raises(ToolError, match="confirm=true"):
        server._tool_manager.get_tool("create_instance").fn(
            instance_name="vm-1",
            instance_type="CPU-2x-8GB",
            vpc_id="vpc-1",
            subnet_id="subnet-1",
            ssh_key_name="ssh-key-1",
            security_group_ids=["sg-1"],
            existing_volume_ids=[_VOLUME_KRN],
            region="In-Bangalore-1",
            confirm=False,
        )
    mock_client.highlvlvpc.create_instance.assert_not_called()


def test_asg_read_contract_has_bounded_required_pagination() -> None:
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    by_vpc = server._tool_manager.get_tool("list_asgs_by_vpc").parameters["properties"]
    templates = server._tool_manager.get_tool("list_launch_templates").parameters
    assert by_vpc["page"]["default"] == 1
    assert by_vpc["size"]["default"] == 50
    assert by_vpc["size"]["maximum"] == 100
    assert "vpc_id" in templates["required"]


def test_asg_launch_template_region_restriction_is_visible_in_schema() -> None:
    admin = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    update_template = admin._tool_manager.get_tool("update_launch_template")
    region = update_template.parameters["properties"]["region"]
    assert region.get("const", region.get("enum")) in (
        "In-Bangalore-1",
        ["In-Bangalore-1"],
    )


def test_sdk_required_identifiers_are_required_in_tool_schemas() -> None:
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    delete_template = server._tool_manager.get_tool("delete_launch_template").parameters
    describe_node_group = server._tool_manager.get_tool("describe_kks_node_group").parameters
    delete_node_group = server._tool_manager.get_tool("delete_kks_node_group").parameters
    delete_addon = server._tool_manager.get_tool("delete_kks_addon").parameters

    assert {"template_id", "template_name", "version"}.issubset(delete_template["required"])
    assert "cluster_krn" in describe_node_group["required"]
    assert "cluster_krn" in delete_node_group["required"]
    assert "cluster_krn" in delete_addon["required"]


def test_vpc_creation_schema_never_prompts_for_security_groups() -> None:
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    tool = server._tool_manager.get_tool("create_vpc")
    properties = set(tool.parameters["properties"])
    assert not any("security" in name or "rule" in name for name in properties)
    assert not any("ingress" in name or "egress" in name for name in properties)


def test_combined_security_group_rule_schema_derives_only_all_protocol_ports() -> None:
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    parameters = server._tool_manager.get_tool("create_security_group").parameters

    assert "rule" not in parameters["required"]
    assert parameters["properties"]["rule_requested_by_user"]["default"] is False
    assert "Never infer" in parameters["properties"]["rule_requested_by_user"]["description"]
    rule_schema = parameters["$defs"]["SecurityGroupRuleSpec"]
    assert set(rule_schema["required"]) == {
        "direction",
        "ethertype",
        "protocol",
        "remote_ip_prefix",
    }
    assert rule_schema["properties"]["port_min"]["default"] is None
    assert rule_schema["properties"]["port_max"]["default"] is None
    assert rule_schema["properties"]["protocol"]["enum"] == [
        "tcp",
        "udp",
        "icmp",
        "all",
    ]


def test_public_security_group_ingress_needs_separate_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    server = create_server(
        _settings(tool_profile="admin", enable_sensitive_tools=True)
    )
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    tool = server._tool_manager.get_tool("create_security_group_rule")
    with pytest.raises(ToolError, match="allow_public_ingress=true"):
        tool.fn(
            vpc_id="vpc-1",
            direction="ingress",
            ethertype="ipv4",
            protocol="tcp",
            port_min=443,
            port_max=443,
            remote_ip_prefix="0.0.0.0/0",
            region="In-Bangalore-1",
            confirm=True,
        )


def test_create_and_attach_rule_rolls_back_partial_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.securityGroup.create_rule.return_value = {"id": "rule-1"}
    mock_client.securityGroup.attach_rule.side_effect = RuntimeError("attach failed")
    server = create_server(
        _settings(tool_profile="admin", enable_sensitive_tools=True)
    )
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    tool = server._tool_manager.get_tool("create_and_attach_security_group_rule")
    with pytest.raises(ToolError, match="was rolled back"):
        tool.fn(
            security_group_id="sg-1",
            vpc_id="vpc-1",
            direction="ingress",
            ethertype="ipv4",
            protocol="tcp",
            port_min=443,
            port_max=443,
            remote_ip_prefix="203.0.113.10/32",
            region="In-Bangalore-1",
            confirm=True,
        )
    mock_client.securityGroup.delete_rule.assert_called_once_with(
        "rule-1", x_region="In-Bangalore-1"
    )


def test_tool_output_recursively_redacts_secret_fields() -> None:
    value = {
        "access_key_id": "visible-id",
        "secret_key": "do-not-expose",
        "nested": {"authorization": "Bearer do-not-expose", "public_key": "visible"},
    }
    result = to_jsonable(value)
    assert result["access_key_id"] == "visible-id"
    assert result["secret_key"] == "***REDACTED***"
    assert result["nested"]["authorization"] == "***REDACTED***"
    assert result["nested"]["public_key"] == "visible"


def test_generated_none_reads_return_actual_raw_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"items": [], "source": "mock-api"}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    cloud_client = KrutrimClient(
        api_key="test",
        http_client=http_client,
        max_retries=0,
    )
    server = create_server(_settings(tool_profile="admin", enable_sensitive_tools=True))
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: cloud_client)
    region = "In-Bangalore-1"
    cases = {
        "list_asgs": {"region": region},
        "list_asgs_by_vpc": {"vpc_krn": "vpc-1"},
        "list_launch_templates": {"vpc_id": "vpc-1", "region": region},
        "list_kks_clusters": {},
        "describe_kks_cluster": {"cluster_krn": "cluster-1"},
        "get_kks_kubeconfig": {"cluster_krn": "cluster-1"},
        "list_kks_flavors": {},
        "list_kks_addons_catalog": {},
        "list_kks_node_groups": {"cluster_krn": "cluster-1"},
        "describe_kks_node_group": {
            "nodegroup_krn": "node-1",
            "cluster_krn": "cluster-1",
        },
        "list_kks_cluster_addons": {"cluster_krn": "cluster-1"},
        "list_dns_zones": {},
        "get_dns_zone": {"zone_id": "zone-1"},
        "list_dns_records": {"zone_id": "zone-1"},
    }
    try:
        for tool_name, arguments in cases.items():
            result = server._tool_manager.get_tool(tool_name).fn(**arguments)
            assert result.data == payload, tool_name
    finally:
        cloud_client.close()


def test_doctor_outputs_non_secret_configuration(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure_bearer_environment(monkeypatch)
    main(["--doctor"])
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["ok"] is True
    assert payload["transport"] == "stdio"
    assert payload["catalog"] == "all-supported"
    assert payload["tool_count"] == 138
    assert "profile" not in payload
    assert payload["credentials_configured"] is True
    assert payload["configuration_ready"] is True
    assert payload["credential_ready"] is True
    assert payload["authentication_verified"] is False
    assert payload["compatibility_disabled_tools"] == [
        "create_asg",
        "create_launch_template",
    ]
    assert _TEST_IAM_JWT not in output
    assert _TEST_REFRESH_TOKEN not in output


def test_legacy_profile_cli_is_ignored_with_warning(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure_bearer_environment(monkeypatch)

    with pytest.warns(RuntimeWarning, match="--profile is deprecated and ignored"):
        main(["--doctor", "--profile", "core-readonly"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["tool_count"] == 138
    assert payload["read_only"] is False


@pytest.mark.parametrize(
    "name",
    (
        "KRUTRIM_API_KEY",
        "KRUTRIM_CLIENT_API_KEY",
        "krutrim_client_API_KEY",
        "KRUTRIMCLIENT_API_KEY",
    ),
)
def test_doctor_rejects_removed_api_key_environment_variables(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setenv(name, "legacy-api-key")

    with pytest.raises(
        SystemExit,
        match="API-key authentication is disabled",
    ):
        main(["--doctor"])


def test_doctor_accepts_access_and_refresh_token_pair_without_exposing_them(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    access_token, refresh_token = make_iam_token_pair()
    monkeypatch.delenv("KRUTRIM_API_KEY", raising=False)
    monkeypatch.delenv("KRUTRIM_CLIENT_API_KEY", raising=False)
    monkeypatch.delenv("krutrim_client_API_KEY", raising=False)
    monkeypatch.delenv("KRUTRIMCLIENT_API_KEY", raising=False)
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", access_token)
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", refresh_token)

    main(["--doctor"])

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["ok"] is True
    assert payload["credential_kind"] == "access_token"
    assert payload["refresh_token_configured"] is True
    assert payload["access_token_refresh_required"] is False
    assert payload["authentication_verified"] is False
    assert payload["credential_ready"] is True
    assert access_token not in output
    assert refresh_token not in output


def test_doctor_does_not_consume_refresh_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from krutrim_mcp_server import client as client_mod

    monkeypatch.delenv("KRUTRIM_API_KEY", raising=False)
    monkeypatch.delenv("KRUTRIM_CLIENT_API_KEY", raising=False)
    monkeypatch.delenv("krutrim_client_API_KEY", raising=False)
    monkeypatch.delenv("KRUTRIMCLIENT_API_KEY", raising=False)
    access_token, refresh_token = make_iam_token_pair(access_exp=1)
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", access_token)
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", refresh_token)
    post = MagicMock(side_effect=AssertionError("doctor must not call IAM"))
    monkeypatch.setattr(client_mod.httpx, "post", post)

    main(["--doctor"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["credential_ready"] is True
    assert payload["access_token_refresh_required"] is True
    assert payload["authentication_verified"] is False
    post.assert_not_called()


def test_access_token_without_refresh_token_fails_fast(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KRUTRIM_API_KEY", raising=False)
    monkeypatch.delenv("KRUTRIM_CLIENT_API_KEY", raising=False)
    monkeypatch.delenv("krutrim_client_API_KEY", raising=False)
    monkeypatch.delenv("KRUTRIMCLIENT_API_KEY", raising=False)
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", _TEST_IAM_JWT)
    monkeypatch.delenv("KRUTRIM_REFRESH_TOKEN", raising=False)

    with pytest.raises(
        SystemExit,
        match="KRUTRIM_ACCESS_TOKEN is set, but KRUTRIM_REFRESH_TOKEN is missing",
    ):
        main(["--doctor"])


def test_doctor_rejects_api_key_even_with_bearer_pair(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("KRUTRIM_API_KEY", "api-key")
    monkeypatch.setenv("KRUTRIM_ACCESS_TOKEN", _TEST_IAM_JWT)
    monkeypatch.setenv("KRUTRIM_REFRESH_TOKEN", "refresh-token")

    with pytest.raises(
        SystemExit,
        match="API-key authentication is disabled",
    ):
        main(["--doctor"])


def test_doctor_does_not_accept_login_credentials(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("KRUTRIM_API_KEY", raising=False)
    monkeypatch.delenv("KRUTRIM_CLIENT_API_KEY", raising=False)
    monkeypatch.delenv("krutrim_client_API_KEY", raising=False)
    monkeypatch.delenv("KRUTRIMCLIENT_API_KEY", raising=False)
    monkeypatch.setenv("KRUTRIM_EMAIL", "user@example.com")
    monkeypatch.setenv("KRUTRIM_PASSWORD", "not-a-runtime-credential")
    monkeypatch.setenv("KRUTRIM_IS_ROOT_USER", "true")

    with pytest.raises(SystemExit) as stopped:
        main(["--doctor"])

    payload = json.loads(capsys.readouterr().out)
    assert stopped.value.code == 1
    assert payload["ok"] is False
    assert payload["credentials_configured"] is False
    assert payload["credential_ready"] is False
