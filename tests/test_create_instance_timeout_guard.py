"""Regression tests for create_instance timeout handling (issue #110).

A client-side timeout on create_instance is a false negative: the VM is
usually still created and billing server-side, and list_instances does not
show it promptly. The MCP layer must (a) give the create call a timeout that
can actually complete, and (b) never report a bare timeout that invites a
blind retry.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import httpx
import pytest
from krutrim_client import APITimeoutError
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.server import create_server
from krutrim_mcp_server.tools.compute import instances as instance_tools

_VPC_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:vpc:"
    "00000000-0000-4000-8000-000000000001"
)
_SUBNET_KRN = (
    "krn:vpc:In-Bangalore-1:customer-test:account-test:subnet:"
    "00000000-0000-4000-8000-000000000003"
)


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "api_key": "test-api-key-for-offline-tests",
        "base_url": "https://cloud.olakrutrim.com",
        "default_region": "",
        "read_only": False,
        "log_level": "ERROR",
        "client_max_retries": 0,
        "tool_profile": "all",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _create_instance_args() -> dict[str, object]:
    return {
        "instance_name": "timeout-guard-vm",
        "instance_type": "CPU-2x-8GB",
        "vpc_id": _VPC_KRN,
        "subnet_id": _SUBNET_KRN,
        "ssh_key_name": "test-key",
        "security_group_ids": ["security-group-1"],
        "image_krn": "image-1",
        "region": "In-Bangalore-1",
        "confirm": True,
    }


def _prepared_server(
    monkeypatch: pytest.MonkeyPatch,
    mock_client: MagicMock,
    settings: Settings,
):
    from krutrim_mcp_server import client as client_mod

    server = create_server(settings)
    monkeypatch.setattr(client_mod.get_session(), "get_client", lambda: mock_client)
    monkeypatch.setattr(instance_tools, "validate_compute_flavor_name", MagicMock())
    monkeypatch.setattr(
        instance_tools, "verify_subnet_membership", MagicMock()
    )
    return server


def test_default_create_timeout_is_long_enough_to_complete() -> None:
    # Live creates have needed several minutes; a 30s default guarantees the
    # ambiguous-timeout path is exercised on every slow create.
    assert _settings().create_timeout_seconds >= 540


def test_create_instance_uses_the_dedicated_create_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.create_instance.return_value = {"task_id": "task-1"}
    server = _prepared_server(
        monkeypatch, mock_client, _settings(create_timeout_seconds=555.0)
    )

    result = server._tool_manager.get_tool("create_instance").fn(
        **_create_instance_args()
    )

    assert result.ok is True
    call = mock_client.highlvlvpc.create_instance.call_args
    assert call.kwargs["timeout"] == 555.0


def test_create_instance_timeout_error_warns_against_blind_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = MagicMock()
    mock_client.highlvlvpc.create_instance.side_effect = APITimeoutError(
        request=httpx.Request("POST", "https://cloud.olakrutrim.com")
    )
    server = _prepared_server(monkeypatch, mock_client, _settings())

    with pytest.raises(ToolError) as excinfo:
        server._tool_manager.get_tool("create_instance").fn(
            **_create_instance_args()
        )

    message = str(excinfo.value)
    assert "still created server-side" in message
    assert "Do NOT retry" in message
    assert "timeout-guard-vm" in message
    assert "list_instances" in message


_TIMEOUT_FIELDS = (
    ("client_timeout_seconds", "KRUTRIM_CLIENT_TIMEOUT_SECONDS", 30.0),
    ("create_timeout_seconds", "KRUTRIM_CREATE_TIMEOUT_SECONDS", 600.0),
)


@pytest.fixture
def isolated_timeout_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in os.environ:
        if name.upper().startswith(("KRUTRIM", "KPOD")):
            monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.mark.parametrize("field, env_name, default", _TIMEOUT_FIELDS)
@pytest.mark.parametrize("raw", ["nan", "inf", "-inf", "1e309", "0", "-0.5"])
def test_timeouts_from_env_reject_non_positive_or_non_finite_values(
    isolated_timeout_env: pytest.MonkeyPatch,
    field: str, env_name: str, default: float, raw: str,
) -> None:
    isolated_timeout_env.setenv(env_name, raw)
    with pytest.raises(ValueError, match=f"{env_name} must be finite and greater than 0"):
        Settings.from_env()


@pytest.mark.parametrize("field, env_name, default", _TIMEOUT_FIELDS)
@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 0.0, -0.5])
def test_direct_settings_reject_non_positive_or_non_finite_timeouts(
    field: str, env_name: str, default: float, value: float,
) -> None:
    with pytest.raises(ValueError, match=f"{env_name} must be finite and greater than 0"):
        _settings(**{field: value}).validate()


@pytest.mark.parametrize("field, env_name, default", _TIMEOUT_FIELDS)
@pytest.mark.parametrize("raw", [None, "", "  ", "0.001", "555.5", "1e3"])
def test_timeouts_preserve_defaults_and_positive_finite_values(
    isolated_timeout_env: pytest.MonkeyPatch,
    field: str, env_name: str, default: float, raw: str | None,
) -> None:
    if raw is not None:
        isolated_timeout_env.setenv(env_name, raw)
    expected = float(raw) if raw and raw.strip() else default
    configured = Settings.from_env()
    assert getattr(configured, field) == expected
    _settings(**{field: expected}).validate()
