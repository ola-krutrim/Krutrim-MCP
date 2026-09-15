"""Guarded, bounded Sandbox file access; never access the MCP host filesystem."""

import re
from collections.abc import Callable
from typing import Annotated, Any

from krutrim_client import APIError
from pydantic import Field, StrictBool, StrictInt

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.logging_utils import redact_text
from krutrim_mcp_server.tools import CONFIRM_FIELD, ToolSuccess, run_tool, settings
from krutrim_mcp_server.tools.sandbox._responses import safe_response
from krutrim_mcp_server.tools.sandbox.execution import _model_result

_MAX_FILE_BYTES = 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9_:-]+")


def _validate_target(sandbox_id: str, path: str) -> None:
    if not isinstance(sandbox_id, str) or not _IDENTIFIER.fullmatch(sandbox_id):
        raise ValueError("sandbox_id must be an exact path-safe Sandbox ID or KRN")
    if (
        not isinstance(path, str)
        or not path
        or path != path.strip()
        or not path.isprintable()
        or "\\" in path
        or "%" in path
        or any(part in {".", ".."} for part in path.split("/"))
    ):
        raise ValueError("path must be an exact printable Sandbox path without traversal")


def _run_file_tool(fn: Callable[[], Any]) -> ToolSuccess:
    def protected() -> Any:
        try:
            return safe_response(fn())
        except APIError as exc:
            status = getattr(exc, "status_code", None)
            detail = f"HTTP {status}" if status is not None else type(exc).__name__
            raise ValueError(
                f"Sandbox file request failed ({detail}); "
                "response omitted to protect file content. "
                "For a mutation, verify the remote state before retrying."
            ) from None

    return run_tool(protected)


def register(mcp: Any) -> None:
    @mcp.tool()
    def make_sandbox_directory(
        sandbox_id: str, path: str, confirm: StrictBool = CONFIRM_FIELD
    ) -> ToolSuccess:
        """Create a directory inside the remote Sandbox."""

        def _run() -> Any:
            ensure_writable(settings(), "make_sandbox_directory")
            ensure_confirmed(confirm, "make_sandbox_directory", sandbox_id)
            _validate_target(sandbox_id, path)
            files = get_session().get_client().with_options(max_retries=0).sandbox.api.files
            return files.make_directory(sandbox_id, path=path)

        return _run_file_tool(_run)

    @mcp.tool()
    def move_sandbox_file(
        sandbox_id: str, path: str, new_path: str, confirm: StrictBool = CONFIRM_FIELD
    ) -> ToolSuccess:
        """Move or rename a remote Sandbox file; the destination may be overwritten."""

        def _run() -> Any:
            ensure_writable(settings(), "move_sandbox_file")
            ensure_confirmed(confirm, "move_sandbox_file", sandbox_id)
            _validate_target(sandbox_id, path)
            _validate_target(sandbox_id, new_path)
            files = get_session().get_client().with_options(max_retries=0).sandbox.api.files
            return files.move(sandbox_id, path=path, new_path=new_path)

        return _run_file_tool(_run)

    @mcp.tool()
    def delete_sandbox_file(
        sandbox_id: str, path: str, confirm: StrictBool = CONFIRM_FIELD
    ) -> ToolSuccess:
        """Delete a remote Sandbox file or directory. Review the exact path first."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_sandbox_file")
            ensure_confirmed(confirm, "delete_sandbox_file", sandbox_id)
            _validate_target(sandbox_id, path)
            files = get_session().get_client().with_options(max_retries=0).sandbox.api.files
            return files.delete(sandbox_id, path=path)

        return _run_file_tool(_run)

    @mcp.tool()
    def list_sandbox_files(
        sandbox_id: str, path: str, depth: Annotated[StrictInt, Field(ge=1, le=10)] = 1
    ) -> ToolSuccess:
        """List remote Sandbox directory entries, with explicit path and bounded depth."""

        def _run() -> Any:
            _validate_target(sandbox_id, path)
            if type(depth) is not int or not 1 <= depth <= 10:
                raise ValueError("depth must be an integer between 1 and 10")
            return (
                get_session()
                .get_client()
                .sandbox.api.files.list(sandbox_id, path=path, depth=depth)
            )

        return _run_file_tool(_run)

    @mcp.tool()
    def stat_sandbox_file(sandbox_id: str, path: str) -> ToolSuccess:
        """Describe a remote Sandbox file or directory without reading its contents."""

        def _run() -> Any:
            _validate_target(sandbox_id, path)
            return get_session().get_client().sandbox.api.files.stat(sandbox_id, path=path)

        return _run_file_tool(_run)

    @mcp.tool()
    def read_sandbox_file(sandbox_id: str, path: str) -> ToolSuccess:
        """Read at most 1 MiB of UTF-8 text from a Sandbox, with credential redaction.

        Binary files are unsupported. No files are written to the MCP host.
        """

        def _run() -> Any:
            _validate_target(sandbox_id, path)
            files = get_session().get_client().sandbox.api.files
            content = bytearray()
            with files.with_streaming_response.download(sandbox_id, path=path) as response:
                for chunk in response.iter_bytes(chunk_size=65536):
                    content.extend(chunk)
                    if len(content) > _MAX_FILE_BYTES:
                        raise ValueError("Sandbox file exceeds the 1 MiB MCP limit")
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("Sandbox file is not UTF-8 text") from None
            return {"path": path, "content": redact_text(text), "size_bytes": len(content)}

        return _run_file_tool(_run)

    @mcp.tool()
    def write_sandbox_file(
        sandbox_id: str,
        path: str,
        content: str,
        confirm: StrictBool = CONFIRM_FIELD,
    ) -> ToolSuccess:
        """Write UTF-8 text to a remote Sandbox file, overwriting any existing file.

        content is literal text, never a path on the MCP server host.
        """

        def _run() -> Any:
            ensure_writable(settings(), "write_sandbox_file")
            ensure_confirmed(confirm, "write_sandbox_file", sandbox_id)
            _validate_target(sandbox_id, path)
            if not isinstance(content, str) or len(content.encode("utf-8")) > _MAX_FILE_BYTES:
                raise ValueError("content must be UTF-8 text of at most 1 MiB")
            result = (
                get_session()
                .get_client()
                .with_options(max_retries=0)
                .sandbox.api.files.upload(sandbox_id, path=path, content=content.encode("utf-8"))
            )
            return _model_result(result, (content,))

        return _run_file_tool(_run)
