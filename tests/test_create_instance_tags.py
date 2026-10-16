"""create_instance forwards optional tags to the SDK."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from tests.test_create_instance_timeout_guard import (
    _create_instance_args,
    _prepared_server,
    _settings,
)


def _create(monkeypatch: pytest.MonkeyPatch, **extra: object) -> MagicMock:
    client = MagicMock()
    client.highlvlvpc.create_instance.return_value = {"task_id": "task-1"}
    server = _prepared_server(monkeypatch, client, _settings())
    server._tool_manager.get_tool("create_instance").fn(**_create_instance_args(), **extra)
    return client


@pytest.mark.parametrize(
    "tags",
    [
        ["prod", "team-a"],
        [{"key": "managed_by", "value": "agent"}, {"key": "owner", "value": "qa"}],
        ["mixed", {"key": "k", "value": ""}],
    ],
)
def test_tags_are_forwarded_to_the_sdk(monkeypatch: pytest.MonkeyPatch, tags: list) -> None:
    client = _create(monkeypatch, tags=tags)
    assert client.highlvlvpc.create_instance.call_args.kwargs["tags"] == tags


@pytest.mark.parametrize("extra", [{}, {"tags": None}, {"tags": []}])
def test_tags_are_omitted_when_not_given(monkeypatch: pytest.MonkeyPatch, extra: dict) -> None:
    client = _create(monkeypatch, **extra)
    assert "tags" not in client.highlvlvpc.create_instance.call_args.kwargs


@pytest.mark.parametrize(
    "tags",
    [
        "not-a-list",
        [""],
        [1],
        [None],
        [["nested"]],
        [{"key": "k", "value": 1}],
        [{"": "v"}],
        ["x" * 257],
        [f"t{i}" for i in range(51)],
    ],
)
def test_invalid_tags_are_rejected_before_any_sdk_call(
    monkeypatch: pytest.MonkeyPatch, tags: object
) -> None:
    client = MagicMock()
    server = _prepared_server(monkeypatch, client, _settings())
    with pytest.raises(ToolError):
        asyncio.run(
            server.call_tool("create_instance", {**_create_instance_args(), "tags": tags})
        )
    assert client.highlvlvpc.create_instance.call_count == 0


def test_tags_parameter_is_in_the_tool_schema() -> None:
    from krutrim_mcp_server.server import create_server

    tool = create_server(_settings()).__dict__["_tool_manager"].get_tool("create_instance")
    props = tool.parameters["properties"]
    assert "tags" in props
    assert "tags" not in tool.parameters.get("required", [])


@pytest.mark.parametrize(
    "tags",
    [["a"], [{"key": "k", "value": "v"}], ["a", {"key": "k", "value": ""}]],
)
def test_valid_tags_pass_tool_validation_end_to_end(
    monkeypatch: pytest.MonkeyPatch, tags: list
) -> None:
    client = MagicMock()
    client.highlvlvpc.create_instance.return_value = {"task_id": "task-1"}
    server = _prepared_server(monkeypatch, client, _settings())
    asyncio.run(server.call_tool("create_instance", {**_create_instance_args(), "tags": tags}))
    assert client.highlvlvpc.create_instance.call_args.kwargs["tags"] == tags
