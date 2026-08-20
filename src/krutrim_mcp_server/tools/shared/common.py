"""Shared helpers for MCP tool modules."""

from typing import Any


def drop_none(values: dict[str, Any]) -> dict[str, Any]:
    """Return a copy without None values so client defaults remain intact."""
    return {key: value for key, value in values.items() if value is not None}
