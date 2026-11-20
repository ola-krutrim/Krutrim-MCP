"""IAM MCP tools (read-only; use the Cloud Console for IAM changes)."""

from typing import Annotated, Any

from pydantic import Field

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
from krutrim_mcp_server.adapters.iam import require_iam_krn
from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.tools import run_tool

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
