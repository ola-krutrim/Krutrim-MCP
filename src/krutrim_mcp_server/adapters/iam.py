"""Direct IAM adapters for public Cloud group and membership discovery APIs."""

import re
from typing import Any
from urllib.parse import quote

import httpx
from krutrim_client import KrutrimClient

from krutrim_mcp_server.adapters._http import required_json_response, response_payload

_IAM_BASE_PATH = "/iam/v1"
_KCS_IAM_KRN = re.compile(
    r"^kcs::[^:\s]+::[^:\s]+::[^:\s]+::iam::(?P<kind>users|groups|roles)::[^:\s]+$"
)
_COLON_IAM_KRN = re.compile(
    r"^krn:iam:[^:\s]+:[^:\s]+:(?P<kind>user|users|group|groups|role|roles):"
    r"[^:\s]+(?::[^:\s]+)*$"
)
_IAM_RESOURCE_KINDS = {
    "user": {"user", "users"},
    "group": {"group", "groups"},
    "role": {"role", "roles"},
}


def _required_identifier(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty identifier")
    return value.strip()


def require_iam_krn(value: str, *, resource: str, field: str) -> str:
    """Require a complete IAM KRN of the requested resource type."""
    normalized = _required_identifier(value, field=field)
    match = _KCS_IAM_KRN.fullmatch(normalized) or _COLON_IAM_KRN.fullmatch(normalized)
    if match is None or match.group("kind") not in _IAM_RESOURCE_KINDS[resource]:
        raise ValueError(
            f"{field} must be a full IAM {resource} KRN, not a UUID or name"
        )
    return normalized


def require_iam_krn_list(values: list[str], *, resource: str, field: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ValueError(f"{field} must contain at least one full IAM {resource} KRN")
    return [
        require_iam_krn(value, resource=resource, field=f"{field}[{index}]")
        for index, value in enumerate(values)
    ]


def _list_response(
    response: httpx.Response,
    *,
    operation: str,
    key: str,
    allow_empty_envelope: bool = False,
) -> list[Any]:
    """Normalize IAM's legacy array and current paginated-object responses."""
    payload = required_json_response(
        response,
        expected_type=(list, dict),
        operation=operation,
    )
    if isinstance(payload, list):
        return payload
    values = payload.get(key)
    if isinstance(values, list):
        return values
    if allow_empty_envelope and payload.get("totalCount") == 0:
        return []
    raise ValueError(f"{operation} returned an object without a {key} list")


def list_iam_users(client: KrutrimClient) -> list[Any]:
    """List IAM users visible to the authenticated principal."""
    response = client.get(f"{_IAM_BASE_PATH}/users", cast_to=httpx.Response)
    return _list_response(
        response,
        operation="list_iam_users",
        key="users",
    )


def list_iam_groups(client: KrutrimClient) -> list[Any]:
    """List IAM groups visible to the authenticated principal."""
    response = client.get(f"{_IAM_BASE_PATH}/groups", cast_to=httpx.Response)
    return _list_response(
        response,
        operation="list_iam_groups",
        key="groups",
        allow_empty_envelope=True,
    )


def get_iam_group(client: KrutrimClient, group_krn: str) -> dict[str, Any]:
    """Get an IAM group by its KRN."""
    normalized_krn = require_iam_krn(group_krn, resource="group", field="group_krn")
    response = client.get(
        f"{_IAM_BASE_PATH}/groups/{quote(normalized_krn, safe=':')}",
        cast_to=httpx.Response,
    )
    return required_json_response(response, expected_type=dict, operation="get_iam_group")


def create_iam_group(
    client: KrutrimClient,
    *,
    name: str,
    description: str | None,
) -> dict[str, Any]:
    """Create an IAM group using the public Cloud group contract."""
    normalized_name = _required_identifier(name, field="name")
    body: dict[str, Any] = {"name": normalized_name}
    if description is not None:
        normalized_description = description.strip()
        if normalized_description:
            body["description"] = normalized_description
    response = client.post(
        f"{_IAM_BASE_PATH}/group",
        cast_to=httpx.Response,
        body=body,
    )
    return response_payload(response)


def delete_iam_group(client: KrutrimClient, group_krn: str) -> dict[str, Any]:
    """Delete an IAM group by its KRN."""
    normalized_krn = require_iam_krn(group_krn, resource="group", field="group_krn")
    response = client.delete(
        f"{_IAM_BASE_PATH}/groups/{quote(normalized_krn, safe=':')}",
        cast_to=httpx.Response,
    )
    return response_payload(response)


def list_iam_group_roles(client: KrutrimClient, group_krn: str) -> list[Any]:
    """List the roles currently attached to an IAM group."""
    normalized_krn = require_iam_krn(group_krn, resource="group", field="group_krn")
    response = client.get(
        f"{_IAM_BASE_PATH}/grouproleinfo",
        cast_to=httpx.Response,
        options={"params": {"groupId": normalized_krn}},
    )
    return required_json_response(response, expected_type=list, operation="list_iam_group_roles")


def list_iam_user_groups(client: KrutrimClient, user_krn: str) -> list[Any]:
    """List the IAM groups currently assigned to a user."""
    normalized_krn = require_iam_krn(user_krn, resource="user", field="user_krn")
    response = client.get(
        f"{_IAM_BASE_PATH}/usergroup",
        cast_to=httpx.Response,
        options={"params": {"userId": normalized_krn}},
    )
    return required_json_response(response, expected_type=list, operation="list_iam_user_groups")


def list_iam_user_roles(client: KrutrimClient, user_krn: str) -> list[Any]:
    """List the IAM roles currently assigned to a user."""
    normalized_krn = require_iam_krn(user_krn, resource="user", field="user_krn")
    response = client.get(
        f"{_IAM_BASE_PATH}/userrole",
        cast_to=httpx.Response,
        options={"params": {"userId": normalized_krn}},
    )
    return required_json_response(response, expected_type=list, operation="list_iam_user_roles")
