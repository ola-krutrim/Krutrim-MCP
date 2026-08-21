"""Wire-contract tests for public IAM group and membership discovery tools."""

from unittest.mock import MagicMock

import httpx

from krutrim_mcp_server.adapters.iam import (
    create_iam_group,
    delete_iam_group,
    get_iam_group,
    list_iam_group_roles,
    list_iam_groups,
    list_iam_user_groups,
    list_iam_user_roles,
    list_iam_users,
    require_iam_krn,
    require_iam_krn_list,
)

USER_KRN = "kcs::global::1234567890::customer-1::iam::users::user-1"
GROUP_KRN = "kcs::global::1234567890::customer-1::iam::groups::group-1"
ROLE_KRN = "kcs::global::1234567890::customer-1::iam::roles::role-1"


def test_iam_group_and_user_discovery_routes() -> None:
    client = MagicMock()
    client.get.side_effect = [
        httpx.Response(200, json=[{"krn": "user-1"}]),
        httpx.Response(200, json=[{"krn": "group-1"}]),
        httpx.Response(200, json={"krn": "group-1"}),
        httpx.Response(200, json=[{"krn": "role-1"}]),
        httpx.Response(200, json=[{"krn": "group-1"}]),
        httpx.Response(200, json=[{"krn": "role-1"}]),
    ]

    assert list_iam_users(client) == [{"krn": "user-1"}]
    assert list_iam_groups(client) == [{"krn": "group-1"}]
    assert get_iam_group(client, GROUP_KRN) == {"krn": "group-1"}
    assert list_iam_group_roles(client, GROUP_KRN) == [{"krn": "role-1"}]
    assert list_iam_user_groups(client, USER_KRN) == [{"krn": "group-1"}]
    assert list_iam_user_roles(client, USER_KRN) == [{"krn": "role-1"}]

    assert client.get.call_args_list[0].args[0] == "/iam/v1/users"
    assert client.get.call_args_list[1].args[0] == "/iam/v1/groups"
    assert client.get.call_args_list[2].args[0] == f"/iam/v1/groups/{GROUP_KRN}"
    assert client.get.call_args_list[3].kwargs["options"] == {"params": {"groupId": GROUP_KRN}}
    assert client.get.call_args_list[4].kwargs["options"] == {"params": {"userId": USER_KRN}}
    assert client.get.call_args_list[5].kwargs["options"] == {"params": {"userId": USER_KRN}}


def test_iam_krn_guards_reject_partial_or_wrong_resource_identifiers() -> None:
    assert require_iam_krn(USER_KRN, resource="user", field="user_id") == USER_KRN
    assert require_iam_krn(GROUP_KRN, resource="group", field="group_id") == GROUP_KRN
    assert require_iam_krn(ROLE_KRN, resource="role", field="role_id") == ROLE_KRN
    assert require_iam_krn_list([ROLE_KRN], resource="role", field="role_ids") == [ROLE_KRN]

    for value, resource, field in (
        ("user-uuid", "user", "user_id"),
        ("platform-admins", "group", "group_id"),
        (USER_KRN, "role", "role_id"),
    ):
        try:
            require_iam_krn(value, resource=resource, field=field)
        except ValueError as exc:
            assert "full IAM" in str(exc)
        else:
            raise AssertionError("expected a partial or wrong-type KRN to be rejected")


def test_list_iam_users_accepts_the_live_pagination_envelope() -> None:
    client = MagicMock()
    client.get.return_value = httpx.Response(
        200,
        json={"totalCount": 1, "users": [{"krn": "user-1"}]},
    )

    assert list_iam_users(client) == [{"krn": "user-1"}]


def test_list_iam_users_rejects_malformed_pagination_envelope() -> None:
    client = MagicMock()
    client.get.return_value = httpx.Response(200, json={"totalCount": 0})

    try:
        list_iam_users(client)
    except ValueError as exc:
        assert str(exc) == "list_iam_users returned an object without a users list"
    else:
        raise AssertionError("expected malformed users envelope to be rejected")


def test_list_iam_groups_accepts_live_pagination_envelopes() -> None:
    client = MagicMock()
    client.get.return_value = httpx.Response(
        200,
        json={"totalCount": 1, "groups": [{"krn": "group-1"}]},
    )

    assert list_iam_groups(client) == [{"krn": "group-1"}]

    client.get.return_value = httpx.Response(
        200,
        json={"message": "No groups found", "totalCount": 0},
    )

    assert list_iam_groups(client) == []


def test_iam_group_create_and_delete_wire_contract() -> None:
    client = MagicMock()
    client.post.return_value = httpx.Response(201, json={"krn": "group-1"})
    client.delete.return_value = httpx.Response(200, json={"deleted": True})

    assert create_iam_group(client, name="platform-admins", description="Platform team") == {
        "krn": "group-1"
    }
    assert delete_iam_group(client, GROUP_KRN) == {"deleted": True}

    client.post.assert_called_once_with(
        "/iam/v1/group",
        cast_to=httpx.Response,
        body={"name": "platform-admins", "description": "Platform team"},
    )
    client.delete.assert_called_once_with(
        f"/iam/v1/groups/{GROUP_KRN}",
        cast_to=httpx.Response,
    )
