"""VM instance-template and batch-create tool regression tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server

_TEMPLATE_KRN = (
    "krn:vm:In-Bangalore-1:customer-test:account-test:template:"
    "00000000-0000-4000-8000-000000000001"
)


def _settings(**overrides: object) -> Settings:
    values = dict(
        api_key="test-api-key-for-offline-tests",
        base_url="https://cloud.olakrutrim.com",
        default_region="",
        read_only=False,
        log_level="ERROR",
        client_max_retries=0,
        tool_profile="admin",
        enable_sensitive_tools=True,
    )
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _gpu_flavor_entry() -> dict[str, object]:
    return {
        "subject": "In-Bangalore-1",
        "groupBy": {
            "flavorid": "11111111-1111-4111-8111-111111111111",
            "flavorname": "A100-NVLINK-Standard-1x",
            "cpus": "16",
            "cpuram": "120",
            "cost": "100",
            "currency": "INR",
            "unit": "hour",
            "flavorstatus": "active",
            "type": "GPU",
        },
    }


def _configure_gpu_flavor_catalog(mock_client: MagicMock) -> None:
    request = httpx.Request(
        "GET",
        "https://cloud.olakrutrim.com/api/v1/flavor/compute?type=GPU",
    )
    mock_client.get.return_value = httpx.Response(
        200,
        json=[_gpu_flavor_entry()],
        request=request,
    )


def _use_client(monkeypatch: pytest.MonkeyPatch, mock_client: MagicMock) -> None:
    from krutrim_mcp_server import client as client_mod

    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)


def test_instance_template_tools_are_always_in_the_unified_catalog() -> None:
    expected = {
        "list_instance_templates",
        "describe_instance_template",
        "create_instance_template",
        "batch_create_vms",
        "delete_instance_template",
    }
    compute = create_server(_settings(tool_profile="compute"))
    compute_names = {tool.name for tool in compute._tool_manager.list_tools()}
    assert expected <= compute_names

    core = create_server(_settings(tool_profile="core-readonly"))
    core_names = {tool.name for tool in core._tool_manager.list_tools()}
    assert expected <= core_names
    assert compute_names == core_names


def test_instance_template_tool_schemas_require_region_and_confirmation() -> None:
    server = create_server(_settings())
    create = server._tool_manager.get_tool("create_instance_template").parameters
    batch = server._tool_manager.get_tool("batch_create_vms").parameters
    delete = server._tool_manager.get_tool("delete_instance_template").parameters

    assert {"region", "confirm", "volume_type", "volume_size"} <= set(create["required"])
    assert create["properties"]["volume_type"]["enum"] == ["HNSS", "HNSS_Encrypted"]
    assert batch["properties"]["count"]["minimum"] == 1
    assert {"region", "confirm", "template_krn"} <= set(batch["required"])
    assert {"region", "confirm", "template_krn"} <= set(delete["required"])


def test_create_instance_template_forwards_gpu_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    _configure_gpu_flavor_catalog(mock_client)
    mock_client.highlvlvpc.create_instance_template.return_value = {
        "template_krn": _TEMPLATE_KRN
    }
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)

    result = server._tool_manager.get_tool("create_instance_template").fn(
        template_name="gpu-template",
        instance_type="A100-NVLINK-Standard-1x",
        instance_flavor_type="GPU",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        ssh_key_name="ssh-key-1",
        security_group_ids=[" sg-1 "],
        image_krn="image-1",
        volume_name="gpu-template-volume",
        volume_size=50,
        volume_type="HNSS",
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    assert mock_client.get.call_args.kwargs["options"]["params"] == {"type": "GPU"}
    kwargs = mock_client.highlvlvpc.create_instance_template.call_args.kwargs
    assert kwargs["name"] == "gpu-template"
    assert kwargs["instanceType"] == "A100-NVLINK-Standard-1x"
    assert kwargs["isGpu"] is True
    assert kwargs["security_groups"] == ["sg-1"]
    assert kwargs["region"] == "In-Bangalore-1"


def test_template_reads_forward_region_and_exact_krn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.list_instance_templates.return_value = {"templates": []}
    mock_client.highlvlvpc.retrieve_instance_template.return_value = {
        "template_krn": _TEMPLATE_KRN
    }
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)

    listed = server._tool_manager.get_tool("list_instance_templates").fn(
        region="In-Bangalore-1",
        page=2,
        limit=25,
    )
    described = server._tool_manager.get_tool("describe_instance_template").fn(
        template_krn=_TEMPLATE_KRN,
        region="In-Bangalore-1",
    )

    assert listed.ok is True
    assert described.ok is True
    mock_client.highlvlvpc.list_instance_templates.assert_called_once_with(
        x_region="In-Bangalore-1",
        page=2,
        limit=25,
    )
    mock_client.highlvlvpc.retrieve_instance_template.assert_called_once_with(
        template_krn=_TEMPLATE_KRN,
        x_region="In-Bangalore-1",
    )


def test_batch_create_vms_preflights_exact_template_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.retrieve_instance_template.return_value = {
        "template_krn": _TEMPLATE_KRN
    }
    mock_client.highlvlvpc.batch_create_vms.return_value = {
        "job_id": "job-1",
        "total_count": 3,
    }
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)

    result = server._tool_manager.get_tool("batch_create_vms").fn(
        template_krn=_TEMPLATE_KRN,
        count=3,
        instance_name="worker",
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.highlvlvpc.retrieve_instance_template.assert_called_once_with(
        template_krn=_TEMPLATE_KRN,
        x_region="In-Bangalore-1",
    )
    mock_client.highlvlvpc.batch_create_vms.assert_called_once_with(
        template_krn=_TEMPLATE_KRN,
        count=3,
        instanceName="worker",
        x_region="In-Bangalore-1",
    )


def test_batch_create_vms_blocks_changed_template_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.retrieve_instance_template.return_value = {
        "template_krn": _TEMPLATE_KRN.replace("000000000001", "000000000002")
    }
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)

    with pytest.raises(ToolError, match="exact requested KRN"):
        server._tool_manager.get_tool("batch_create_vms").fn(
            template_krn=_TEMPLATE_KRN,
            count=3,
            instance_name="worker",
            region="In-Bangalore-1",
            confirm=True,
        )

    mock_client.highlvlvpc.batch_create_vms.assert_not_called()


def test_delete_instance_template_preflights_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.retrieve_instance_template.return_value = {
        "template_krn": _TEMPLATE_KRN
    }
    mock_client.highlvlvpc.delete_instance_template.return_value = {"message": "deleted"}
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)

    result = server._tool_manager.get_tool("delete_instance_template").fn(
        template_krn=_TEMPLATE_KRN,
        region="In-Bangalore-1",
        confirm=True,
    )

    assert result.ok is True
    mock_client.highlvlvpc.retrieve_instance_template.assert_called_once()
    mock_client.highlvlvpc.delete_instance_template.assert_called_once_with(
        template_krn=_TEMPLATE_KRN,
        x_region="In-Bangalore-1",
    )


@pytest.mark.parametrize("tool_name", ["batch_create_vms", "delete_instance_template"])
def test_template_mutations_require_confirmation_before_client_access(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
) -> None:
    mock_client = MagicMock()
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)
    arguments: dict[str, object] = {
        "template_krn": _TEMPLATE_KRN,
        "region": "In-Bangalore-1",
        "confirm": False,
    }
    if tool_name == "batch_create_vms":
        arguments.update({"count": 2, "instance_name": "worker"})

    with pytest.raises(ToolError, match="confirm=true"):
        server._tool_manager.get_tool(tool_name).fn(**arguments)

    mock_client.highlvlvpc.retrieve_instance_template.assert_not_called()


def test_template_krn_must_match_selected_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    server = create_server(_settings())
    _use_client(monkeypatch, mock_client)

    with pytest.raises(ToolError, match="does not match selected region"):
        server._tool_manager.get_tool("describe_instance_template").fn(
            template_krn=_TEMPLATE_KRN,
            region="In-Hyderabad-1",
        )

    mock_client.highlvlvpc.retrieve_instance_template.assert_not_called()
