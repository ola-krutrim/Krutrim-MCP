"""Compatibility helpers for generated Krutrim SDK behavior."""

from collections.abc import Callable
from typing import Any

from krutrim_client import KrutrimClient

from krutrim_mcp_server.config import KNOWN_REGIONS

_REGION_ARGUMENTS = ("x_region", "region", "region_id", "x_region_id")
_COMPATIBLE_HIGHLVLVPC_VALIDATORS = {
    "validate_create_image_parameters",
    "validate_create_port_parameters",
    "validate_delete_vpc_parameters",
    "validate_get_vpc_task_status_params",
    "validate_list_instance_info_parameters",
    "validate_retrieve_instance_parameters",
    "validate_search_networks_parameters",
}


def sdk_response_json(call: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
    """Normalize bodies from SDK methods whose declared result is incorrectly None."""
    return sdk_raw_result(call, *args, **kwargs)


def sdk_raw_result(call: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
    """Normalize a raw SDK response, including valid empty mutation responses."""
    response = call(*args, **kwargs)
    http_response = getattr(response, "http_response", response)
    status_code = getattr(http_response, "status_code", None)
    read_method = getattr(response, "read", None)
    content = read_method() if callable(read_method) else getattr(http_response, "content", b"")
    if not content:
        return {"status_code": status_code, "completed": True}
    try:
        return response.json()
    except ValueError:
        return {
            "status_code": status_code,
            "body": getattr(http_response, "text", ""),
        }


def _find_known_region(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
    for key in _REGION_ARGUMENTS:
        value = kwargs.get(key)
        if value in KNOWN_REGIONS:
            return str(value)
    for value in args:
        if value in KNOWN_REGIONS:
            return str(value)
    return None


def _is_stale_region_validation(exc: ValueError) -> bool:
    message = str(exc)
    return (
        "region" in message
        and "In-Bangalore-1" in message
        and "In-Hyderabad-1" not in message
    )


def _patch_validator(resource: Any, name: str) -> bool:
    validator = getattr(resource, name, None)
    if not callable(validator) or getattr(validator, "_krutrim_mcp_patched", False):
        return False

    def patched_validator(*args: Any, **kwargs: Any) -> Any:
        try:
            return validator(*args, **kwargs)
        except ValueError as exc:
            region = _find_known_region(args, kwargs)
            if _is_stale_region_validation(exc) and region:
                # Substitute only during validation so other fields remain checked.
                compatibility_region = KNOWN_REGIONS[0]
                validated_args = tuple(
                    compatibility_region if value == region else value for value in args
                )
                validated_kwargs = dict(kwargs)
                for key in _REGION_ARGUMENTS:
                    if validated_kwargs.get(key) == region:
                        validated_kwargs[key] = compatibility_region
                return validator(*validated_args, **validated_kwargs)
            raise

    patched_validator._krutrim_mcp_patched = True  # type: ignore[attr-defined]
    setattr(resource, name, patched_validator)
    return True


def patch_client_compatibility(client: KrutrimClient) -> None:
    """Patch only verified high-level VPC sync-validator drift."""
    resource = getattr(client, "highlvlvpc", None)
    if resource is None:
        return
    for name in _COMPATIBLE_HIGHLVLVPC_VALIDATORS:
        _patch_validator(resource, name)
