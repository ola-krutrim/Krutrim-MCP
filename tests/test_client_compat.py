"""Compatibility tests for generated client behavior."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import httpx
import pytest
from krutrim_client import APITimeoutError, KrutrimClient

from krutrim_mcp_server.adapters.compute import delete_instance_async
from krutrim_mcp_server.adapters.kbs import (
    change_volume_type,
    create_volume,
    create_volume_backup,
    create_volume_backup_policy,
    create_volume_snapshot,
    create_volume_snapshot_policy,
    delete_volume_backup,
    delete_volume_backup_policy,
    delete_volume_snapshot,
    delete_volume_snapshot_policy,
    extend_volume,
    force_delete_volume,
    list_volume_backups,
    list_volume_snapshots,
    list_volume_types,
    list_volumes,
    restore_volume_backup,
    retrieve_volume_backup,
    retrieve_volume_snapshot,
    update_volume,
    update_volume_snapshot,
)
from krutrim_mcp_server.adapters.vpc import (
    create_vpc_without_security_fields,
    delete_floating_ip,
)
from krutrim_mcp_server.compat import (
    patch_client_compatibility,
    sdk_raw_result,
    sdk_response_json,
)

_VOLUME_KRN = (
    "krn:kbs:In-Bangalore-1:customer-test:account-test:volume:"
    "00000000-0000-4000-8000-000000000001"
)
_VPC_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:vpc:"
    "00000000-0000-4000-8000-000000000002"
)
_FLOATING_IP_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:floatingIP:"
    "00000000-0000-4000-8000-000000000006"
)
_IMAGE_KRN = (
    "krn:vm:In-Bangalore-1:default:default:image:"
    "00000000-0000-4000-8000-000000000005"
)
_SNAPSHOT_KRN = (
    "krn:kbs:In-Bangalore-1:customer-test:account-test:snapshot:"
    "00000000-0000-4000-8000-000000000003"
)
_BACKUP_KRN = (
    "krn:kbs:In-Bangalore-1:customer-test:account-test:backup:"
    "00000000-0000-4000-8000-000000000004"
)
_BACKUP_ID = "backup-00000000-0000-4000-8000-000000000004"


class FakeHighlvlVPC:
    __module__ = "krutrim_client.resources.highlvlvpc"

    def validate_get_vpc_task_status_params(self, *, task_id: str, x_region: str):
        if x_region == "In-Hyderabad-1":
            raise ValueError("'x_region' must be either 'In-Bangalore-1'")
        return None


class FakeASG:
    __module__ = "krutrim_client.resources.asg.asgV1"

    def validate_create_launch_template_parameters(self, *, x_region: str, **kwargs):
        if x_region == "In-Hyderabad-1":
            raise ValueError("'x_region' must be 'In-Bangalore-1'")
        if not isinstance(kwargs.get("name"), str):
            raise ValueError("'name' must be a string")
        return None


class FakeClient:
    def __init__(self) -> None:
        self.highlvlvpc = FakeHighlvlVPC()
        self.asgV1 = FakeASG()


def test_all_stale_region_validators_accept_known_config_region() -> None:
    client = FakeClient()
    patch_client_compatibility(client)  # type: ignore[arg-type]

    assert client.highlvlvpc.validate_get_vpc_task_status_params(
        task_id="task-1", x_region="In-Hyderabad-1"
    ) is None


def test_region_compatibility_does_not_bypass_unverified_asg_restrictions() -> None:
    client = FakeClient()
    patch_client_compatibility(client)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="x_region"):
        client.asgV1.validate_create_launch_template_parameters(
            x_region="In-Hyderabad-1", name="valid"
        )


def test_vpc_compat_adapter_uses_exact_no_security_group_contract() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["region"] = request.headers.get("x-region")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            202,
            json={"status": "accepted", "task_id": "task-1"},
            request=request,
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = KrutrimClient(api_key="test", http_client=http_client, max_retries=0)
    try:
        result = create_vpc_without_security_fields(
            client,
            network={"admin_state_up": True, "name": "test-network"},
            subnet={
                "name": "test-subnet",
                "cidr": "10.0.1.0/24",
                "description": "test",
                "gateway_ip": "10.0.1.1",
                "ip_version": "4",
                "ingress": False,
                "egress": False,
            },
            vpc={"name": "test-vpc", "description": "test", "enabled": True},
            x_region="In-Hyderabad-1",
        )
        assert result["task_id"] == "task-1"
        assert captured["path"] == "/v1/highlvlvpc/create_vpc_async"
        assert captured["region"] == "In-Hyderabad-1"
        assert set(captured["body"]) == {"network", "subnet", "vpc"}  # type: ignore[arg-type]
    finally:
        client.close()


def test_vpc_compat_adapter_rejects_non_allowlisted_fields() -> None:
    client = MagicMock(spec=KrutrimClient)
    with pytest.raises(ValueError, match="security_group"):
        create_vpc_without_security_fields(
            client,
            network={"name": "test-network", "security_group": {}},
            subnet={},
            vpc={},
            x_region="In-Bangalore-1",
        )
    client.post.assert_not_called()


def test_vpc_compat_adapter_handles_empty_accepted_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, content=b"", request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        result = create_vpc_without_security_fields(
            client,
            network={"admin_state_up": True, "name": "test-network"},
            subnet={
                "name": "test-subnet",
                "cidr": "10.0.1.0/24",
                "gateway_ip": "10.0.1.1",
                "ip_version": "4",
                "ingress": True,
                "egress": True,
            },
            vpc={"name": "test-vpc", "enabled": True},
            x_region="In-Bangalore-1",
        )
        assert result == {"status_code": 202, "accepted": True}
    finally:
        client.close()


def test_delete_floating_ip_adapter_uses_exact_query_contract() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["query"] = dict(request.url.params)
        captured["region"] = request.headers.get("x-region")
        return httpx.Response(200, json={"message": "deleted"}, request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        result = delete_floating_ip(
            client,
            floating_ip_krn=_FLOATING_IP_KRN,
            x_region="In-Bangalore-1",
        )
        assert result == {"message": "deleted"}
        assert captured == {
            "method": "DELETE",
            "path": "/v1/highlvlvpc/delete_floating_ip",
            "query": {"floating_ip_krn": _FLOATING_IP_KRN},
            "region": "In-Bangalore-1",
        }
    finally:
        client.close()


def test_kbs_volume_create_adapter_uses_current_hidden_az_contract() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(
            method=request.method,
            path=request.url.path,
            tenant=request.headers.get("K-Tenant-ID"),
            region=request.headers.get("x-region"),
            body=json.loads(request.content),
        )
        return httpx.Response(
            202,
            json={"volume": {"id": "volume-1"}, "status": "creating"},
            request=request,
        )

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        result = create_volume(
            client,
            name="production-data-20260711",
            size_gb=50,
            vpc_krn=_VPC_KRN,
            x_region="In-Bangalore-1",
            volume_type="HNSS_Encrypted",
            multiattach=False,
            description="encrypted application data",
        )
        assert result == {
            "status_code": 202,
            "accepted": True,
            "completed": False,
            "response": {"volume": {"id": "volume-1"}, "status": "creating"},
        }
        assert captured == {
            "method": "POST",
            "path": "/kbs/v1/volumes",
            "tenant": _VPC_KRN,
            "region": "In-Bangalore-1",
            "body": {
                "availability_zone": "nova",
                "name": "production-data-20260711",
                "size": 50,
                "volumetype": "HNSS_Encrypted",
                "multiattach": False,
                "description": "encrypted application data",
            },
        }
    finally:
        client.close()


@pytest.mark.parametrize(
    ("source_type", "source_id"),
    [
        ("image", _IMAGE_KRN),
        ("volume", _VOLUME_KRN),
        ("snapshot", _SNAPSHOT_KRN),
    ],
)
def test_kbs_volume_create_adapter_adds_typed_source(
    source_type: str,
    source_id: str,
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            202,
            json={"volume": {"id": "boot-volume-1"}, "status": "creating"},
            request=request,
        )

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        create_volume(
            client,
            name="source-backed-20260714",
            size_gb=50,
            vpc_krn=_VPC_KRN,
            x_region="In-Bangalore-1",
            source_type=source_type,
            source_id=source_id,
        )
        assert captured["body"] == {
            "availability_zone": "nova",
            "name": "source-backed-20260714",
            "size": 50,
            "volumetype": "HNSS",
            "multiattach": False,
            "source": {"id": source_id, "type": source_type},
        }
    finally:
        client.close()


@pytest.mark.parametrize(
    ("create_call", "expected_path", "extra_body"),
    [
        (create_volume_snapshot, "/kbs/v1/snapshots", {}),
        (
            create_volume_backup,
            "/kbs/v1/backups",
            {"incremental": False},
        ),
    ],
)
def test_kbs_copy_adapters_use_exact_verified_contract(
    create_call,
    expected_path: str,
    extra_body: dict[str, object],
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["tenant"] = request.headers.get("K-Tenant-ID")
        captured["region"] = request.headers.get("x-region")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            202,
            json={"id": "copy-1", "status": "creating"},
            request=request,
        )

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        result = create_call(
            client,
            name="nightly-copy-20260711",
            volume_id=_VOLUME_KRN,
            vpc_krn=_VPC_KRN,
            x_region="In-Bangalore-1",
            description="production-safe contract test",
            force=False,
        )
        assert result == {"id": "copy-1", "status": "creating"}
        assert captured == {
            "path": expected_path,
            "tenant": _VPC_KRN,
            "region": "In-Bangalore-1",
            "body": {
                "name": "nightly-copy-20260711",
                "volume_id": _VOLUME_KRN,
                "description": "production-safe contract test",
                "force": False,
                **extra_body,
            },
        }
    finally:
        client.close()


def test_kbs_copy_adapter_omits_optional_fields_and_preserves_empty_202() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(202, content=b"", request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        result = create_volume_snapshot(
            client,
            name="snapshot-20260711",
            volume_id=_VOLUME_KRN,
            vpc_krn=_VPC_KRN,
            x_region="In-Bangalore-1",
        )
        assert result == {"status_code": 202, "accepted": True}
        assert captured["body"] == {
            "name": "snapshot-20260711",
            "description": "",
            "volume_id": _VOLUME_KRN,
            "force": False,
        }
    finally:
        client.close()


@pytest.mark.parametrize(
    ("list_call", "expected_path", "payload"),
    [
        (list_volumes, "/kbs/v1/volumes", [{"id": _VOLUME_KRN}]),
        (
            list_volume_snapshots,
            "/kbs/v1/snapshots",
            [{"id": _SNAPSHOT_KRN, "status": "available"}],
        ),
        (
            list_volume_backups,
            "/kbs/v1/backups",
            [{"id": _BACKUP_ID, "status": "available"}],
        ),
    ],
)
def test_kbs_list_adapters_use_exact_verified_read_contract(
    list_call,
    expected_path: str,
    payload: list[dict[str, object]],
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            tenant=request.headers.get("K-Tenant-ID"),
            region=request.headers.get("x-region"),
            body=request.read(),
        )
        return httpx.Response(200, json=payload, request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        result = list_call(
            client,
            vpc_krn=_VPC_KRN,
            x_region="In-Bangalore-1",
        )
        assert result == payload
        assert captured == {
            "method": "GET",
            "path": expected_path,
            "query": b"",
            "tenant": _VPC_KRN,
            "region": "In-Bangalore-1",
            "body": b"",
        }
    finally:
        client.close()


@pytest.mark.parametrize(
    ("retrieve_call", "id_argument", "resource_id", "expected_path", "payload"),
    [
        (
            retrieve_volume_snapshot,
            "snapshot_id",
            _SNAPSHOT_KRN,
            f"/kbs/v1/snapshots/{_SNAPSHOT_KRN}",
            {"id": _SNAPSHOT_KRN, "status": "available"},
        ),
        (
            retrieve_volume_backup,
            "backup_id",
            _BACKUP_ID,
            f"/kbs/v1/backups/{_BACKUP_ID}",
            {"id": _BACKUP_ID, "status": "available"},
        ),
    ],
)
def test_kbs_retrieve_adapters_use_exact_verified_read_contract(
    retrieve_call,
    id_argument: str,
    resource_id: str,
    expected_path: str,
    payload: dict[str, object],
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            tenant=request.headers.get("K-Tenant-ID"),
            region=request.headers.get("x-region"),
            body=request.read(),
        )
        return httpx.Response(200, json=payload, request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        result = retrieve_call(
            client,
            **{
                id_argument: resource_id,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
        )
        assert result == payload
        assert captured == {
            "method": "GET",
            "path": expected_path,
            "query": b"",
            "tenant": _VPC_KRN,
            "region": "In-Bangalore-1",
            "body": b"",
        }
    finally:
        client.close()


@pytest.mark.parametrize(
    (
        "delete_call",
        "id_argument",
        "resource_id",
        "expected_path",
        "resource_type",
    ),
    [
        (
            delete_volume_snapshot,
            "snapshot_id",
            _SNAPSHOT_KRN,
            f"/kbs/v1/snapshots/{_SNAPSHOT_KRN}",
            "volume_snapshot",
        ),
        (
            delete_volume_backup,
            "backup_id",
            _BACKUP_ID,
            f"/kbs/v1/backups/{_BACKUP_ID}",
            "volume_backup",
        ),
    ],
)
def test_kbs_delete_adapters_treat_empty_204_as_completed(
    delete_call,
    id_argument: str,
    resource_id: str,
    expected_path: str,
    resource_type: str,
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            tenant=request.headers.get("K-Tenant-ID"),
            region=request.headers.get("x-region"),
            body=request.read(),
        )
        return httpx.Response(204, content=b"", request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        result = delete_call(
            client,
            **{
                id_argument: resource_id,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
        )
        assert result == {
            "resource_type": resource_type,
            "resource_id": resource_id,
            "status_code": 204,
            "completed": True,
        }
        assert captured == {
            "method": "DELETE",
            "path": expected_path,
            "query": b"",
            "tenant": _VPC_KRN,
            "region": "In-Bangalore-1",
            "body": b"",
        }
    finally:
        client.close()


@pytest.mark.parametrize(
    ("delete_call", "id_argument", "resource_id", "resource_type"),
    [
        (
            delete_volume_snapshot,
            "snapshot_id",
            _SNAPSHOT_KRN,
            "volume_snapshot",
        ),
        (delete_volume_backup, "backup_id", _BACKUP_ID, "volume_backup"),
    ],
)
def test_kbs_delete_adapters_keep_202_accepted_distinct_from_completion(
    delete_call,
    id_argument: str,
    resource_id: str,
    resource_type: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, content=b"", request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        result = delete_call(
            client,
            **{
                id_argument: resource_id,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
        )
        assert result == {
            "resource_type": resource_type,
            "resource_id": resource_id,
            "status_code": 202,
            "accepted": True,
            "completed": False,
        }
    finally:
        client.close()


def test_kbs_read_adapter_rejects_an_unverified_success_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json=[], request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        with pytest.raises(ValueError, match="unexpected HTTP 202; expected 200"):
            list_volumes(
                client,
                vpc_krn=_VPC_KRN,
                x_region="In-Bangalore-1",
            )
    finally:
        client.close()


@pytest.mark.parametrize(
    ("delete_call", "id_argument", "resource_id"),
    [
        (delete_volume_snapshot, "snapshot_id", _SNAPSHOT_KRN),
        (delete_volume_backup, "backup_id", _BACKUP_ID),
    ],
)
def test_kbs_delete_adapters_reject_an_unverified_success_status(
    delete_call,
    id_argument: str,
    resource_id: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"deleted": True}, request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        with pytest.raises(ValueError, match="unexpected HTTP 200; expected 204 or 202"):
            delete_call(
                client,
                **{
                    id_argument: resource_id,
                    "vpc_krn": _VPC_KRN,
                    "x_region": "In-Bangalore-1",
                },
            )
    finally:
        client.close()


@pytest.mark.parametrize(
    ("delete_call", "id_argument", "resource_id"),
    [
        (delete_volume_snapshot, "snapshot_id", _SNAPSHOT_KRN),
        (delete_volume_backup, "backup_id", _BACKUP_ID),
    ],
)
def test_kbs_delete_adapters_do_not_retry_an_uncertain_timeout(
    delete_call,
    id_argument: str,
    resource_id: str,
) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("uncertain delete result", request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    try:
        with pytest.raises(APITimeoutError, match="Request timed out"):
            delete_call(
                client,
                **{
                    id_argument: resource_id,
                    "vpc_krn": _VPC_KRN,
                    "x_region": "In-Bangalore-1",
                },
            )
        assert attempts == 1
    finally:
        client.close()


@pytest.mark.parametrize(
    ("read_call", "id_arguments", "payload", "expected_type"),
    [
        (list_volumes, {}, {"items": []}, "list"),
        (list_volume_snapshots, {}, {"items": []}, "list"),
        (list_volume_backups, {}, {"items": []}, "list"),
        (
            retrieve_volume_snapshot,
            {"snapshot_id": _SNAPSHOT_KRN},
            [{"id": _SNAPSHOT_KRN}],
            "dict",
        ),
        (
            retrieve_volume_backup,
            {"backup_id": _BACKUP_ID},
            [{"id": _BACKUP_ID}],
            "dict",
        ),
    ],
)
def test_kbs_read_adapters_reject_unverified_response_shapes(
    read_call,
    id_arguments: dict[str, str],
    payload: object,
    expected_type: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload, request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        with pytest.raises(ValueError, match=rf"expected {expected_type}"):
            read_call(
                client,
                vpc_krn=_VPC_KRN,
                x_region="In-Bangalore-1",
                **id_arguments,
            )
    finally:
        client.close()


@pytest.mark.parametrize(
    ("adapter_call", "arguments", "error"),
    [
        (
            list_volumes,
            {"vpc_krn": "vpc-id", "x_region": "In-Bangalore-1"},
            "full source VPC KRN",
        ),
        (
            retrieve_volume_snapshot,
            {
                "snapshot_id": "snapshot-id",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "snapshot_id must be a full Krutrim KBS KRN",
        ),
        (
            delete_volume_snapshot,
            {
                "snapshot_id": _SNAPSHOT_KRN.replace(
                    "customer-test", "other-customer"
                ),
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "scope does not match vpc_krn",
        ),
        (
            retrieve_volume_backup,
            {
                "backup_id": "backup/id",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "exact nonblank path-safe identifier",
        ),
        (
            delete_volume_backup,
            {
                "backup_id": " backup-id",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "exact nonblank path-safe identifier",
        ),
        (
            delete_volume_backup,
            {
                "backup_id": "..",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "exact nonblank path-safe identifier",
        ),
        (
            retrieve_volume_backup,
            {
                "backup_id": _BACKUP_KRN.replace("account-test", "other-account"),
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "scope does not match vpc_krn",
        ),
    ],
)
def test_kbs_lifecycle_adapters_validate_identifiers_before_http(
    adapter_call,
    arguments: dict[str, str],
    error: str,
) -> None:
    client = MagicMock(spec=KrutrimClient)

    with pytest.raises(ValueError, match=error):
        adapter_call(client, **arguments)

    client.get.assert_not_called()
    client.delete.assert_not_called()


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"name": "UPPERCASE"}, "name must be 3-63 lowercase"),
        ({"name": "bad--name"}, "adjacent dots or hyphens"),
        ({"volume_id": "volume-uuid"}, "full Krutrim block-volume KRN"),
        (
            {"volume_id": _VOLUME_KRN.replace("customer-test", "other-customer")},
            "scope does not match vpc_krn",
        ),
        ({"vpc_krn": "tenant-uuid"}, "full source VPC KRN"),
        (
            {"x_region": "In-Hyderabad-1"},
            "vpc_krn region.*does not match selected region",
        ),
    ],
)
def test_kbs_copy_adapter_rejects_invalid_fields_before_http(
    overrides: dict[str, object], error: str
) -> None:
    client = MagicMock(spec=KrutrimClient)
    arguments: dict[str, object] = {
        "name": "snapshot-20260711",
        "volume_id": _VOLUME_KRN,
        "vpc_krn": _VPC_KRN,
        "x_region": "In-Bangalore-1",
    }
    arguments.update(overrides)

    with pytest.raises((TypeError, ValueError), match=error):
        create_volume_snapshot(client, **arguments)  # type: ignore[arg-type]
    client.post.assert_not_called()


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"name": "  "}, "name must be a nonblank string"),
        ({"size_gb": 0}, "positive integer"),
        ({"volume_type": "ssd"}, "HNSS.*HNSS_Encrypted"),
        ({"vpc_krn": "tenant-uuid"}, "full source VPC KRN"),
        (
            {"x_region": "In-Hyderabad-1"},
            "vpc_krn region.*does not match selected region",
        ),
        ({"multiattach": "false"}, "multiattach must be bool"),
        ({"description": 123}, "description must be a string"),
        ({"source_type": "image"}, "source_type and source_id must be provided together"),
        ({"source_id": _IMAGE_KRN}, "source_type and source_id must be provided together"),
        (
            {"source_type": "backup", "source_id": _BACKUP_KRN},
            "source_type must be 'image', 'volume', or 'snapshot'",
        ),
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
            {"source_type": "volume", "source_id": _SNAPSHOT_KRN},
            "volume_id must be a full Krutrim block-volume KRN",
        ),
        (
            {"source_type": "snapshot", "source_id": _VOLUME_KRN},
            "snapshot_id must be a full Krutrim KBS KRN",
        ),
    ],
)
def test_kbs_volume_create_adapter_rejects_invalid_fields_before_http(
    overrides: dict[str, object], error: str
) -> None:
    client = MagicMock(spec=KrutrimClient)
    arguments: dict[str, object] = {
        "name": "volume-20260711",
        "size_gb": 50,
        "vpc_krn": _VPC_KRN,
        "x_region": "In-Bangalore-1",
    }
    arguments.update(overrides)

    with pytest.raises((TypeError, ValueError), match=error):
        create_volume(client, **arguments)  # type: ignore[arg-type]
    client.post.assert_not_called()


def test_kbs_volume_create_adapter_does_not_retry_an_uncertain_timeout() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("uncertain create result", request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    try:
        with pytest.raises(APITimeoutError, match="Request timed out"):
            create_volume(
                client,
                name="volume-20260711",
                size_gb=50,
                vpc_krn=_VPC_KRN,
                x_region="In-Bangalore-1",
            )
        assert attempts == 1
    finally:
        client.close()


def test_kbs_copy_adapter_does_not_retry_an_uncertain_timeout() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("uncertain create result", request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        with pytest.raises(APITimeoutError, match="Request timed out"):
            create_volume_backup(
                client,
                name="primary-20260711",
                volume_id=_VOLUME_KRN,
                vpc_krn=_VPC_KRN,
                x_region="In-Bangalore-1",
            )
        assert attempts == 1
    finally:
        client.close()


@pytest.mark.parametrize(
    (
        "adapter_call",
        "arguments",
        "expected_method",
        "expected_path",
        "expected_query",
        "expected_body",
        "status_code",
    ),
    [
        (
            update_volume_snapshot,
            {
                "snapshot_id": _SNAPSHOT_KRN,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
                "name": "snapshot-renamed",
                "description": "retained snapshot",
                "metadata": {"environment": "test"},
            },
            "PUT",
            f"/kbs/v1/snapshots/{_SNAPSHOT_KRN}",
            {},
            {
                "name": "snapshot-renamed",
                "description": "retained snapshot",
                "metadata": {"environment": "test"},
            },
            200,
        ),
        (
            restore_volume_backup,
            {
                "backup_id": _BACKUP_ID,
                "name": "restored-volume",
                "target_volume_id": _VOLUME_KRN,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "POST",
            f"/kbs/v1/backups/{_BACKUP_ID}/restore",
            {},
            {"name": "restored-volume", "volume_id": _VOLUME_KRN},
            202,
        ),
        (
            extend_volume,
            {
                "volume_id": _VOLUME_KRN,
                "new_size_gb": 200,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "POST",
            f"/kbs/v1/volumes/{_VOLUME_KRN}/action",
            {"op": "extend"},
            {"input": {"newSize": 200}},
            202,
        ),
        (
            update_volume,
            {
                "volume_id": _VOLUME_KRN,
                "name": "volume-renamed",
                "metadata": {"owner": "platform"},
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "PUT",
            f"/kbs/v1/volumes/{_VOLUME_KRN}",
            {},
            {
                "volume": {
                    "name": "volume-renamed",
                    "metadata": {"owner": "platform"},
                }
            },
            200,
        ),
        (
            change_volume_type,
            {
                "volume_id": _VOLUME_KRN,
                "volume_type": "HNSS_Encrypted",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "PUT",
            f"/kbs/v1/volumes/{_VOLUME_KRN}/change_type",
            {},
            {"volume_type": "HNSS_Encrypted"},
            202,
        ),
        (
            force_delete_volume,
            {
                "volume_id": _VOLUME_KRN,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "DELETE",
            f"/kbs/v1/volumes/{_VOLUME_KRN}",
            {"force": "true"},
            None,
            204,
        ),
    ],
)
def test_selected_kbs_mutation_adapters_use_exact_wire_contract(
    adapter_call,
    arguments: dict[str, object],
    expected_method: str,
    expected_path: str,
    expected_query: dict[str, str],
    expected_body: dict[str, object] | None,
    status_code: int,
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(
            method=request.method,
            path=request.url.path,
            query=dict(request.url.params),
            tenant=request.headers.get("K-Tenant-ID"),
            region=request.headers.get("x-region"),
            body=json.loads(request.content) if request.content else None,
        )
        if status_code == 204:
            return httpx.Response(status_code, content=b"", request=request)
        return httpx.Response(
            status_code,
            json={"status": "accepted"},
            request=request,
        )

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    try:
        result = adapter_call(client, **arguments)
        assert result["status_code"] == status_code
        assert captured == {
            "method": expected_method,
            "path": expected_path,
            "query": expected_query,
            "tenant": _VPC_KRN,
            "region": "In-Bangalore-1",
            "body": expected_body,
        }
    finally:
        client.close()


@pytest.mark.parametrize(
    (
        "adapter_call",
        "arguments",
        "expected_method",
        "expected_path",
        "expected_body",
    ),
    [
        (
            create_volume_snapshot_policy,
            {
                "name": "nightly-snapshots",
                "volume_id": _VOLUME_KRN,
                "max_snapshots_allowed": 7,
                "cron": "0 2 * * *",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "POST",
            f"/kbs/v1/volumes/{_VOLUME_KRN}/snapshots/policy",
            {
                "name": "nightly-snapshots",
                "max_snapshots_allowed": 7,
                "cron": "0 2 * * *",
            },
        ),
        (
            create_volume_backup_policy,
            {
                "name": "weekly-backups",
                "volume_id": _VOLUME_KRN,
                "max_backups_allowed": 4,
                "cron": "0 3 * * 0",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "POST",
            f"/kbs/v1/volumes/{_VOLUME_KRN}/backups/policy",
            {
                "name": "weekly-backups",
                "max_backups_allowed": 4,
                "cron": "0 3 * * 0",
            },
        ),
        (
            delete_volume_snapshot_policy,
            {
                "volume_id": _VOLUME_KRN,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "DELETE",
            f"/kbs/v1/volumes/{_VOLUME_KRN}/snapshots/policy",
            None,
        ),
        (
            delete_volume_backup_policy,
            {
                "volume_id": _VOLUME_KRN,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "DELETE",
            f"/kbs/v1/volumes/{_VOLUME_KRN}/backups/policy",
            None,
        ),
    ],
)
def test_kbs_policy_adapters_use_exact_wire_contract(
    adapter_call,
    arguments: dict[str, object],
    expected_method: str,
    expected_path: str,
    expected_body: dict[str, object] | None,
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(
            method=request.method,
            path=request.url.path,
            query=dict(request.url.params),
            tenant=request.headers.get("K-Tenant-ID"),
            region=request.headers.get("x-region"),
            body=json.loads(request.content) if request.content else None,
        )
        status_code = 201 if request.method == "POST" else 204
        return httpx.Response(status_code, content=b"", request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    try:
        result = adapter_call(client, **arguments)
        assert result["status_code"] in {201, 204}
        assert captured == {
            "method": expected_method,
            "path": expected_path,
            "query": {},
            "tenant": _VPC_KRN,
            "region": "In-Bangalore-1",
            "body": expected_body,
        }
    finally:
        client.close()


def test_kbs_list_volume_types_adapter_uses_exact_wire_contract() -> None:
    captured: dict[str, object] = {}
    payload = {"volume_types": ["HNSS", "HNSS_Encrypted"]}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(
            method=request.method,
            path=request.url.path,
            query=dict(request.url.params),
            tenant=request.headers.get("K-Tenant-ID"),
            region=request.headers.get("x-region"),
            body=request.read(),
        )
        return httpx.Response(200, json=payload, request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        assert (
            list_volume_types(
                client,
                vpc_krn=_VPC_KRN,
                x_region="In-Bangalore-1",
            )
            == payload
        )
        assert captured == {
            "method": "GET",
            "path": "/kbs/v1/volumes/types",
            "query": {},
            "tenant": _VPC_KRN,
            "region": "In-Bangalore-1",
            "body": b"",
        }
    finally:
        client.close()


@pytest.mark.parametrize(
    ("adapter_call", "arguments", "error"),
    [
        (
            update_volume_snapshot,
            {
                "snapshot_id": _SNAPSHOT_KRN,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "requires at least one user-supplied",
        ),
        (
            create_volume_snapshot_policy,
            {
                "name": "nightly-snapshots",
                "volume_id": _VOLUME_KRN,
                "max_snapshots_allowed": 0,
                "cron": "0 2 * * *",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "maximum count must be a positive integer",
        ),
        (
            create_volume_backup_policy,
            {
                "name": "weekly-backups",
                "volume_id": _VOLUME_KRN,
                "max_backups_allowed": 4,
                "cron": " 0 3 * * 0",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "cron must be a nonblank printable expression",
        ),
        (
            restore_volume_backup,
            {
                "backup_id": _BACKUP_ID,
                "name": "UPPERCASE",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "restore name must be 3-63 lowercase",
        ),
        (
            extend_volume,
            {
                "volume_id": _VOLUME_KRN,
                "new_size_gb": 0,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "new_size_gb must be a positive integer",
        ),
        (
            update_volume,
            {
                "volume_id": _VOLUME_KRN,
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "requires at least one user-supplied",
        ),
        (
            change_volume_type,
            {
                "volume_id": _VOLUME_KRN,
                "volume_type": "ssd",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "HNSS.*HNSS_Encrypted",
        ),
        (
            force_delete_volume,
            {
                "volume_id": "volume-id",
                "vpc_krn": _VPC_KRN,
                "x_region": "In-Bangalore-1",
            },
            "full Krutrim block-volume KRN",
        ),
        (
            list_volume_types,
            {
                "vpc_krn": "vpc-id",
                "x_region": "In-Bangalore-1",
            },
            "full source VPC KRN",
        ),
    ],
)
def test_selected_kbs_adapters_reject_invalid_inputs_before_http(
    adapter_call,
    arguments: dict[str, object],
    error: str,
) -> None:
    client = MagicMock(spec=KrutrimClient)

    with pytest.raises((TypeError, ValueError), match=error):
        adapter_call(client, **arguments)

    assert not client.method_calls


def test_kbs_selected_mutation_does_not_retry_an_uncertain_timeout() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("uncertain extend result", request=request)

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    try:
        with pytest.raises(APITimeoutError, match="Request timed out"):
            extend_volume(
                client,
                volume_id=_VOLUME_KRN,
                new_size_gb=200,
                vpc_krn=_VPC_KRN,
                x_region="In-Bangalore-1",
            )
        assert attempts == 1
    finally:
        client.close()


def test_sdk_existing_boot_volume_request_uses_async_single_create_contract() -> None:
    captured: dict[str, object] = {}
    volume_krn = (
        "krn:kbs:In-Bangalore-1:customer-test:account-test:volume:"
        "00000000-0000-4000-8000-000000000001"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"message": "accepted", "task_id": "task-1"},
            request=request,
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = KrutrimClient(api_key="test", http_client=http_client, max_retries=0)
    try:
        client.highlvlvpc.create_instance(
            instanceName="vm-from-volume",
            instanceType="CPU-2x-8GB",
            vpc_id="vpc-1",
            subnet_id="subnet-1",
            sshkey_name="ssh-key-1",
            security_groups=["sg-1"],
            user_data="",
            volumes=[volume_krn],
            floating_ip=False,
            delete_on_termination=False,
            region="In-Bangalore-1",
        )

        body = captured["body"]
        assert isinstance(body, dict)
        assert captured["path"] == "/vm/v1/create_instance_async"
        assert body["volumes"] == [volume_krn]
        assert "volume_name" not in body
        assert "volume_size" not in body
        assert "image_krn" not in body
        assert "volumetype" not in body
        assert body["delete_on_termination"] is False
        assert body["count"] == 1
        assert body["isGpu"] is False
    finally:
        client.close()


def test_sdk_delete_instance_uses_async_contract() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["query"] = dict(request.url.params)
        captured["region"] = request.headers.get("x-region")
        return httpx.Response(
            200,
            json={"message": "accepted", "task_id": "task-delete-1"},
            request=request,
        )

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        response = client.highlvlvpc.delete_instance(
            instanceKrn="krn:vm:In-Bangalore-1:test:instance:vm-1",
            deleteVolume=True,
            x_region="In-Bangalore-1",
        )
        assert response.task_id == "task-delete-1"
        assert captured["path"] == "/vm/v1/delete_instance_async"
        assert captured["query"] == {
            "instanceKrn": "krn:vm:In-Bangalore-1:test:instance:vm-1",
            "deleteVolume": "true",
        }
        assert captured["region"] == "In-Bangalore-1"
    finally:
        client.close()


def test_delete_instance_helper_includes_failed_vm_task_id() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["query"] = dict(request.url.params)
        captured["region"] = request.headers.get("x-region")
        return httpx.Response(
            200,
            json={"message": "accepted", "task_id": "task-delete-2"},
            request=request,
        )

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=7,
    )
    try:
        response = delete_instance_async(
            client,
            instance_krn="krn:vm:In-Bangalore-1:test:instance:vm-1",
            delete_volume=True,
            x_region="In-Bangalore-1",
            task_id="failed-create-task-1",
        )
        assert response["task_id"] == "task-delete-2"
        assert captured["path"] == "/vm/v1/delete_instance_async"
        assert captured["query"] == {
            "instanceKrn": "krn:vm:In-Bangalore-1:test:instance:vm-1",
            "deleteVolume": "true",
            "task_id": "failed-create-task-1",
        }
        assert captured["region"] == "In-Bangalore-1"
    finally:
        client.close()


def test_delete_instance_helper_allows_task_only_failed_vm_delete() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["query"] = dict(request.url.params)
        captured["url"] = str(request.url)
        return httpx.Response(
            200,
            json={"message": "accepted", "task_id": "task-delete-3"},
            request=request,
        )

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=7,
    )
    try:
        response = delete_instance_async(
            client,
            instance_krn="",
            delete_volume=True,
            x_region="In-Bangalore-1",
            task_id="failed-create-task-2",
        )
        assert response["task_id"] == "task-delete-3"
        assert "instanceKrn" not in str(captured["url"])
        assert captured["query"] == {
            "deleteVolume": "true",
            "task_id": "failed-create-task-2",
        }
    finally:
        client.close()


def test_sdk_instance_template_and_batch_routes_are_available() -> None:
    captured: list[tuple[str, str]] = []
    template_krn = "krn:vm:In-Bangalore-1:test:template:template-1"

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append((request.method, request.url.path))
        responses = {
            ("POST", "/vm/v1/instance-templates/create"): {
                "name": "template-1",
                "template_krn": template_krn,
            },
            ("GET", "/vm/v1/instance-templates/list"): {
                "templates": [{"name": "template-1", "template_krn": template_krn}],
                "total_count": 1,
            },
            ("GET", "/vm/v1/instance-templates/details"): {
                "name": "template-1",
                "template_krn": template_krn,
            },
            ("POST", "/vm/v1/batch-vm-create"): {
                "job_id": "job-1",
                "total_count": 2,
            },
            ("DELETE", "/vm/v1/instance-templates/delete"): {
                "message": "deleted"
            },
        }
        return httpx.Response(
            200,
            json=responses[(request.method, request.url.path)],
            request=request,
        )

    client = KrutrimClient(
        api_key="test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    try:
        created = client.highlvlvpc.create_instance_template(
            name="template-1",
            vpc_id="vpc-1",
            subnet_id="subnet-1",
            instanceType="CPU-2x-8GB",
            sshkey_name="ssh-key-1",
            region="In-Bangalore-1",
            image_krn="image-1",
            volumetype="HNSS",
            volume_size=50,
            volume_name="template-1-volume",
            security_groups=["sg-1"],
        )
        listed = client.highlvlvpc.list_instance_templates(
            x_region="In-Bangalore-1",
            page=1,
            limit=10,
        )
        described = client.highlvlvpc.retrieve_instance_template(
            template_krn=template_krn,
            x_region="In-Bangalore-1",
        )
        batch = client.highlvlvpc.batch_create_vms(
            template_krn=template_krn,
            count=2,
            instanceName="worker",
            x_region="In-Bangalore-1",
        )
        deleted = client.highlvlvpc.delete_instance_template(
            template_krn=template_krn,
            x_region="In-Bangalore-1",
        )

        assert created.template_krn == template_krn
        assert listed.total_count == 1
        assert described.template_krn == template_krn
        assert batch.job_id == "job-1"
        assert deleted.message == "deleted"
        assert captured == [
            ("POST", "/vm/v1/instance-templates/create"),
            ("GET", "/vm/v1/instance-templates/list"),
            ("GET", "/vm/v1/instance-templates/details"),
            ("POST", "/vm/v1/batch-vm-create"),
            ("DELETE", "/vm/v1/instance-templates/delete"),
        ]
    finally:
        client.close()


@pytest.mark.parametrize(
    ("network", "error"),
    [
        ({"name": "test-network"}, "Missing network fields.*admin_state_up"),
        (
            {"admin_state_up": "true", "name": "test-network"},
            "network.admin_state_up must be bool",
        ),
    ],
)
def test_vpc_compat_adapter_validates_required_field_contract(
    network: dict[str, object],
    error: str,
) -> None:
    client = MagicMock(spec=KrutrimClient)
    with pytest.raises((TypeError, ValueError), match=error):
        create_vpc_without_security_fields(
            client,
            network=network,
            subnet={
                "name": "test-subnet",
                "cidr": "10.0.1.0/24",
                "gateway_ip": "10.0.1.1",
                "ip_version": "4",
                "ingress": True,
                "egress": True,
            },
            vpc={"name": "test-vpc", "enabled": True},
            x_region="In-Bangalore-1",
        )
    client.post.assert_not_called()


def test_raw_sdk_json_recovers_body_discarded_by_generated_method() -> None:
    payload = {"items": [{"krn": "cluster-1"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = KrutrimClient(api_key="test", http_client=http_client, max_retries=0)
    try:
        assert client.kks.clusters.list() is None
        assert (
            sdk_response_json(client.kks.clusters.with_raw_response.list) == payload
        )
    finally:
        client.close()


def test_raw_sdk_result_preserves_successful_text_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="nameserver.example", request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = KrutrimClient(api_key="test", http_client=http_client, max_retries=0)
    try:
        result = sdk_response_json(client.v1.with_raw_response.get_nameserver_ip)
        assert result == {"status_code": 200, "body": "nameserver.example"}
    finally:
        client.close()


def test_sdk_omit_workaround_sends_only_real_json_values() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(202, json={"task_id": "task-1"}, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = KrutrimClient(api_key="test", http_client=http_client, max_retries=0)
    try:
        result = sdk_raw_result(
            client.kks.clusters.with_raw_response.create,
            name="cluster-1",
            vpcKrn="vpc-1",
            subnetKrns="subnet-1",
            podIpv4Cidr="10.10.0.0/16",
            serviceIpv4Cidr="10.20.0.0/16",
            extra_body={},
        )
        assert result == {"task_id": "task-1"}
        assert "Omit" not in str(captured["body"])
        assert "version" not in str(captured["body"])
    finally:
        client.close()


def test_raw_machine_image_create_avoids_broken_sdk_response_parser() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"task_id": "image-task"}, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = KrutrimClient(api_key="test", http_client=http_client, max_retries=0)
    try:
        result = sdk_raw_result(
            client.highlvlvpc.with_raw_response.create_image,
            name="image-1",
            instance_krn="instance-1",
            x_region="In-Bangalore-1",
        )
        assert result == {"task_id": "image-task"}
    finally:
        client.close()
