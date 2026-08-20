"""Shared helpers for MCP tool modules."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, TypeAlias, TypeVar

from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.config import KNOWN_REGIONS, Settings
from krutrim_mcp_server.errors import format_error
from krutrim_mcp_server.serialize import to_jsonable

T = TypeVar("T")
Region: TypeAlias = Literal["In-Bangalore-1", "In-Hyderabad-1"]
VolumeType: TypeAlias = Literal["HNSS", "HNSS_Encrypted"]
REGION_FIELD = Field(
    ...,
    description=(
        "Select the Krutrim Cloud region for this operation. "
        "Do not infer this from KRUTRIM_DEFAULT_REGION."
    ),
)
CONFIRM_FIELD = Field(
    ...,
    description=(
        "Set to true only after the user explicitly confirms the mutating operation, "
        "selected region, and target details."
    ),
)


class ToolSuccess(BaseModel):
    """Stable structured envelope returned by successful Krutrim tools."""

    model_config = ConfigDict(extra="forbid")

    ok: Literal[True] = True
    data: Any


def settings() -> Settings:
    return get_session().settings


def resolve_region(region: str | None = None) -> str:
    if not isinstance(region, str) or not region.strip():
        raise ValueError(
            "region must be selected explicitly by the user for this MCP tool call "
            f"(known: {', '.join(KNOWN_REGIONS)})."
        )
    value = region.strip()
    if value not in KNOWN_REGIONS:
        raise ValueError(
            f"unknown region {value!r}; expected one of: {', '.join(KNOWN_REGIONS)}."
        )
    return value


def run_tool(fn: Callable[[], T]) -> ToolSuccess:
    """Execute a tool body and expose failures through MCP's tool-error channel."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        raise ToolError(format_error(exc)) from exc

    if isinstance(result, ToolSuccess):
        return result
    if isinstance(result, dict) and result.get("ok") is True:
        result = {key: value for key, value in result.items() if key != "ok"}
    return ToolSuccess(data=to_jsonable(result))
