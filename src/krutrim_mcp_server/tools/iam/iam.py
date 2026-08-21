"""IAM MCP tools."""

from typing import Annotated, Any, Optional

from pydantic import Field

from krutrim_mcp_server.adapters.iam import (
    create_iam_group as _create_iam_group,
)
from krutrim_mcp_server.adapters.iam import (
    delete_iam_group as _delete_iam_group,
)
from krutrim_mcp_server.adapters.iam import (
    get_iam_group as _get_iam_group,
)
from krutrim_mcp_server.adapters.iam import (
    list_iam_group_roles as _list_iam_group_roles,
)
from krutrim_mcp_server.adapters.iam import (
    list_iam_groups as _list_iam_groups,
)
from krutrim_mcp_server.adapters.iam import (
    list_iam_user_groups as _list_iam_user_groups,
)
from krutrim_mcp_server.adapters.iam import (
    list_iam_user_roles as _list_iam_user_roles,
)
from krutrim_mcp_server.adapters.iam import (
    list_iam_users as _list_iam_users,
)
from krutrim_mcp_server.adapters.iam import require_iam_krn, require_iam_krn_list
from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import CONFIRM_FIELD, run_tool, settings

PageLimit = Annotated[int, Field(ge=1, le=100)]
Offset = Annotated[int, Field(ge=0)]


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_iam_roles(limit: PageLimit = 100, offset: Offset = 0) -> str:
        """List IAM roles."""

        def _run() -> Any:
            return get_session().get_client().iam.list_roles(limit=limit, offset=offset)

        return run_tool(_run)

    @mcp.tool()
    def get_iam_role(role_krn: str) -> str:
        """Get an IAM role by KRN."""

        def _run() -> Any:
            return get_session().get_client().iam.get_role(
                require_iam_krn(role_krn, resource="role", field="role_krn")
            )

        return run_tool(_run)

    @mcp.tool()
    def list_iam_policies(
        limit: PageLimit = 100,
        offset: Offset = 0,
        krutrim_managed: str = "all",
    ) -> str:
        """List IAM policies."""

        def _run() -> Any:
            return get_session().get_client().iam.list_policies(
                limit=limit,
                offset=offset,
                krutrim_managed=krutrim_managed,
            )

        return run_tool(_run)

    @mcp.tool()
    def get_iam_user(user_krn: str) -> str:
        """Get an IAM user by KRN."""

        def _run() -> Any:
            return get_session().get_client().iam.get_user(
                require_iam_krn(user_krn, resource="user", field="user_krn")
            )

        return run_tool(_run)

    @mcp.tool()
    def list_iam_users() -> str:
        """List IAM users visible to the authenticated principal."""

        return run_tool(lambda: _list_iam_users(get_session().get_client()))

    @mcp.tool()
    def list_iam_groups() -> str:
        """List IAM groups visible to the authenticated principal."""

        return run_tool(lambda: _list_iam_groups(get_session().get_client()))

    @mcp.tool()
    def get_iam_group(group_krn: str) -> str:
        """Get an IAM group by KRN."""

        return run_tool(lambda: _get_iam_group(get_session().get_client(), group_krn))

    @mcp.tool()
    def list_iam_group_roles(group_krn: str) -> str:
        """List roles attached to an IAM group."""

        return run_tool(
            lambda: _list_iam_group_roles(get_session().get_client(), group_krn)
        )

    @mcp.tool()
    def list_iam_user_groups(user_krn: str) -> str:
        """List IAM groups assigned to a user."""

        return run_tool(
            lambda: _list_iam_user_groups(get_session().get_client(), user_krn)
        )

    @mcp.tool()
    def list_iam_user_roles(user_krn: str) -> str:
        """List IAM roles assigned directly to a user."""

        return run_tool(
            lambda: _list_iam_user_roles(get_session().get_client(), user_krn)
        )

    @mcp.tool()
    def create_iam_group(
        name: Annotated[str, Field(min_length=1, max_length=128)],
        description: Optional[str] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create an IAM group. Roles can be managed in the Cloud console."""

        def _run() -> Any:
            ensure_writable(settings(), "create_iam_group")
            ensure_confirmed(confirm, "create_iam_group", name)
            return _create_iam_group(
                get_session().get_client(), name=name, description=description
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_iam_group(group_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete an IAM group by KRN after removing its user assignments."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_iam_group")
            ensure_confirmed(confirm, "delete_iam_group", group_krn)
            return _delete_iam_group(get_session().get_client(), group_krn)

        return run_tool(_run)

    @mcp.tool()
    def create_iam_user(
        user_name: str,
        email: str,
        password: str,
        console_access: bool = False,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create an IAM user.

        The password is sensitive. Use this tool only from a trusted MCP host;
        transcripts and host logs are outside this package's control. Use the
        approved encrypted credential-delivery or out-of-band process where applicable.
        """

        def _run() -> Any:
            ensure_writable(settings(), "create_iam_user")
            ensure_confirmed(confirm, "create_iam_user", user_name)
            return get_session().get_client().iam.create_user(
                user_name=user_name,
                email=email,
                password=password,
                console_access=console_access,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_iam_user(user_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete an IAM user."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_iam_user")
            normalized_user_krn = require_iam_krn(
                user_krn, resource="user", field="user_krn"
            )
            ensure_confirmed(confirm, "delete_iam_user", normalized_user_krn)
            return get_session().get_client().iam.delete_user(normalized_user_krn)

        return run_tool(_run)

    @mcp.tool()
    def delete_iam_role(role_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete an IAM role."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_iam_role")
            normalized_role_krn = require_iam_krn(
                role_krn, resource="role", field="role_krn"
            )
            ensure_confirmed(confirm, "delete_iam_role", normalized_role_krn)
            return get_session().get_client().iam.delete_role(normalized_role_krn)

        return run_tool(_run)

    @mcp.tool()
    def enable_programmatic_access(user_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Enable programmatic access for an IAM user."""

        def _run() -> Any:
            ensure_writable(settings(), "enable_programmatic_access")
            normalized_user_krn = require_iam_krn(
                user_krn, resource="user", field="user_krn"
            )
            ensure_confirmed(confirm, "enable_programmatic_access", normalized_user_krn)
            return get_session().get_client().iam.enable_programmatic_access(normalized_user_krn)

        return run_tool(_run)

    @mcp.tool()
    def reset_programmatic_access(user_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Reset programmatic access for an IAM user."""

        def _run() -> Any:
            ensure_writable(settings(), "reset_programmatic_access")
            normalized_user_krn = require_iam_krn(
                user_krn, resource="user", field="user_krn"
            )
            ensure_confirmed(confirm, "reset_programmatic_access", normalized_user_krn)
            return get_session().get_client().iam.reset_programmatic_access(normalized_user_krn)

        return run_tool(_run)

    @mcp.tool()
    def disable_programmatic_access(user_krn: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Disable programmatic access for an IAM user."""

        def _run() -> Any:
            ensure_writable(settings(), "disable_programmatic_access")
            normalized_user_krn = require_iam_krn(
                user_krn, resource="user", field="user_krn"
            )
            ensure_confirmed(confirm, "disable_programmatic_access", normalized_user_krn)
            return get_session().get_client().iam.disable_programmatic_access(normalized_user_krn)

        return run_tool(_run)

    @mcp.tool()
    def assign_roles_to_user(
        user_id: str,
        role_ids: list[str],
        group_ids: Optional[list[str]] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Assign roles and optional groups to an IAM user."""

        def _run() -> Any:
            ensure_writable(settings(), "assign_roles_to_user")
            normalized_user_krn = require_iam_krn(user_id, resource="user", field="user_id")
            normalized_role_krns = require_iam_krn_list(
                role_ids, resource="role", field="role_ids"
            )
            normalized_group_krns = (
                require_iam_krn_list(group_ids, resource="group", field="group_ids")
                if group_ids
                else []
            )
            ensure_confirmed(confirm, "assign_roles_to_user", normalized_user_krn)
            return get_session().get_client().iam.assign_roles_to_user(
                user_id=normalized_user_krn,
                role_ids=normalized_role_krns,
                group_ids=normalized_group_krns,
            )

        return run_tool(_run)

    @mcp.tool()
    def create_iam_role_with_policies(
        role_name: str,
        description: str,
        policy_ids: list[str],
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create an IAM role and attach policies."""

        def _run() -> Any:
            ensure_writable(settings(), "create_iam_role_with_policies")
            ensure_confirmed(confirm, "create_iam_role_with_policies", role_name)
            return get_session().get_client().iam.create_role_with_policies(
                role_name=role_name,
                description=description,
                policy_ids=policy_ids,
            )

        return run_tool(_run)

    @mcp.tool()
    def attach_policies_to_role(
        role_id: str,
        policy_ids: list[str],
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Attach policies to an IAM role."""

        def _run() -> Any:
            ensure_writable(settings(), "attach_policies_to_role")
            normalized_role_krn = require_iam_krn(role_id, resource="role", field="role_id")
            ensure_confirmed(confirm, "attach_policies_to_role", normalized_role_krn)
            return get_session().get_client().iam.attach_policies_to_role(
                role_id=normalized_role_krn,
                policy_ids=policy_ids,
            )

        return run_tool(_run)
