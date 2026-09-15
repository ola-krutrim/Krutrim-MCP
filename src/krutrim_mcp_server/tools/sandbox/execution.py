"""Guarded low-level Sandbox execution tools (no persistent SDK handles)."""

import json
import re
from collections.abc import Callable
from typing import Annotated, Any, Literal

import httpx
from pydantic import Field, StrictBool, StrictInt, StrictStr

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.logging_utils import redact_text
from krutrim_mcp_server.serialize import to_jsonable
from krutrim_mcp_server.tools import ToolSuccess, run_tool, settings
from krutrim_mcp_server.tools.sandbox._responses import redact_secrets, safe_response

MAX_CONTENT_BYTES = 1024 * 1024
TimeoutSeconds = Annotated[StrictInt, Field(ge=1, le=270)]
SandboxPort = Annotated[StrictInt, Field(ge=1024, le=65535)]
ProxyMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_SERVICE_PATH = re.compile(r"/[A-Za-z0-9/_~.\-]*")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_:-]{1,512}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _identifier(value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("sandbox_id must be an exact path-safe identifier (UUID or KRN)")


def _guard(operation: str, confirm: bool, sandbox_id: str) -> None:
    ensure_writable(settings(), operation)
    # Never reflect unvalidated caller input in a confirmation error.
    ensure_confirmed(confirm, operation, "selected sandbox")
    _identifier(sandbox_id)


def _timeout(value: int) -> None:
    if type(value) is not int or not 1 <= value <= 270:
        raise ValueError("timeout_seconds must be an integer between 1 and 270")


def _command_inputs(command: str, cwd: str | None, envs: dict[str, str] | None) -> None:
    if not isinstance(command, str) or not 1 <= len(command) <= 100000:
        raise ValueError("command must contain 1 to 100000 characters")
    if cwd is not None and (
        not isinstance(cwd, str)
        or not cwd
        or len(cwd) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in cwd)
    ):
        raise ValueError("cwd must be nonempty text without controls, at most 4096 characters")
    if envs is not None and (
        not isinstance(envs, dict)
        or any(
            not isinstance(key, str)
            or not _ENV_NAME.fullmatch(key)
            or not isinstance(value, str)
            or "\0" in value
            for key, value in envs.items()
        )
    ):
        raise ValueError("envs must map environment variable names to text without NUL")
    if len(json.dumps([command, cwd, envs]).encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError("command request exceeds the 1 MiB limit")


def _port(value: int) -> None:
    if type(value) is not int or not 1024 <= value <= 65535:
        raise ValueError("port must be an integer between 1024 and 65535")


def _proxy_inputs(method: str, path: str, json_body: Any, content: str | None) -> None:
    if not isinstance(method, str) or method not in _METHODS:
        raise ValueError("method must be GET, POST, PUT, PATCH, DELETE, HEAD, or OPTIONS")
    if (
        not isinstance(path, str)
        or len(path) > 4096
        or not _SERVICE_PATH.fullmatch(path)
        or "//" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        raise ValueError(
            "path must be a single-slash relative service path; "
            "URL, query, encoding, and traversal are forbidden"
        )
    if json_body is not None and content is not None:
        raise ValueError("json_body and content are mutually exclusive")
    if content is not None and not isinstance(content, str):
        raise ValueError("content must be text")
    try:
        encoded = (
            content.encode("utf-8")
            if content is not None
            else json.dumps(json_body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("proxy body must be valid JSON or UTF-8 text") from None
    if len(encoded) > MAX_CONTENT_BYTES:
        raise ValueError("proxy request exceeds the 1 MiB limit")


class _NoRedirectHTTPClient(httpx.Client):
    """Borrow the SDK transport without mutating/closing its shared HTTP client.

    SDK 0.6.1 has no per-request follow_redirects option. A small send facade
    enforces it, including when the session's HTTPX default enables redirects.
    Its own unused connection pool is closed normally by the context manager.
    """

    def __init__(self, source: httpx.Client) -> None:
        super().__init__()
        self._source = source

    def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        kwargs["follow_redirects"] = False
        return self._source.send(request, **kwargs)


class _ResponseError(ValueError):
    """Safe fixed-text errors which contain no backend or caller content."""


def _sdk_call(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except _ResponseError:
        raise
    except Exception:
        # SDK errors may embed commands, arbitrary env values, body, or headers.
        raise RuntimeError(
            "Sandbox request failed; request/response details withheld. Mutations are not retried; "
            "the outcome may be unknown. Inspect sandbox state before another attempt."
        ) from None


def _mutation_api() -> Any:
    return get_session().get_client().with_options(max_retries=0).sandbox.api


def _redact(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    value = redact_secrets(value, secrets)
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {_redact(key): _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _bounded_result(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    value = to_jsonable(_redact(value, secrets))
    if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > MAX_CONTENT_BYTES:
        raise _ResponseError("Sandbox response exceeds the 1 MiB MCP limit; response withheld")
    return value


def _model_result(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    status = getattr(value, "status", None)
    if isinstance(status, int) and status >= 400:
        raise _ResponseError(
            "Sandbox returned an error; response details withheld. Mutations are not retried."
        )
    try:
        data = safe_response(value, secrets)
    except Exception:
        raise _ResponseError("Invalid Sandbox response; response details withheld") from None
    # Omit backend message/extra fields, which can echo request secrets.
    return _bounded_result({"status": data.get("status"), "data": data.get("data")})


def _proxy_response(response: Any) -> dict[str, Any]:
    media_type = response.headers.get("content-type", "text/plain").split(";", 1)[0].lower()
    if not (
        media_type.startswith("text/")
        or media_type == "application/json"
        or media_type.endswith("+json")
    ):
        raise _ResponseError(
            "Sandbox proxy returns only JSON or UTF-8 text; binary response withheld"
        )
    raw = bytearray()
    for chunk in response.iter_bytes(chunk_size=65536):
        raw.extend(chunk)
        if len(raw) > MAX_CONTENT_BYTES:
            raise _ResponseError(
                "Sandbox proxy response exceeds the 1 MiB limit; response withheld"
            )
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise _ResponseError(
            "Sandbox proxy response is not UTF-8 text; response withheld"
        ) from None
    if any(ord(char) < 32 and char not in "\t\r\n" for char in text):
        raise _ResponseError("Sandbox proxy response contains binary controls; response withheld")
    try:
        body = json.loads(text)
    except json.JSONDecodeError:
        body = text
    return _bounded_result({"status_code": response.status_code, "body": body})


def register(mcp: Any) -> None:
    @mcp.tool()
    def sandbox_proxy_request(
        sandbox_id: StrictStr,
        method: ProxyMethod,
        path: StrictStr,
        confirm: StrictBool,
        json_body: Any = None,
        content: StrictStr | None = None,
        timeout_seconds: TimeoutSeconds = 60,
    ) -> ToolSuccess:
        """Request a sandbox service path; even GET is a destructive mutation.

        No caller headers, full URLs, query strings, or encoded paths are accepted.
        Paths use ASCII letters/digits, /, _, -, ~, and non-traversal dots only.
        Request/response limit: 1 MiB. Responses are redacted JSON or UTF-8 text;
        response headers and binary content are never returned. No automatic retries.
        """

        def _run() -> Any:
            _guard("sandbox_proxy_request", confirm, sandbox_id)
            _timeout(timeout_seconds)
            _proxy_inputs(method, path, json_body, content)

            def _request() -> Any:
                client = get_session().get_client()
                with _NoRedirectHTTPClient(client._client) as http_client:
                    api = client.with_options(max_retries=0, http_client=http_client).sandbox.api
                    with api.proxy.with_streaming_response.request(
                        sandbox_id,
                        method,
                        path,
                        json=json_body,
                        content=content,
                        headers={"Content-Type": "text/plain; charset=utf-8"}
                        if content is not None
                        else None,
                        max_retries=0,
                        timeout=timeout_seconds,
                    ) as response:
                        return _proxy_response(response)

            return _sdk_call(_request)

        return run_tool(_run)

    @mcp.tool()
    def close_sandbox_port(
        sandbox_id: StrictStr,
        port: SandboxPort,
        confirm: StrictBool,
    ) -> ToolSuccess:
        """Close a publicly exposed sandbox port after user confirmation."""

        def _run() -> Any:
            _guard("close_sandbox_port", confirm, sandbox_id)
            _port(port)

            def _close() -> None:
                # The SDK's typed close method discards bodies, including HTTP
                # 200 envelopes that report failure. Preserve bodyless 204 only.
                response = _mutation_api().ports.with_raw_response.close(sandbox_id, port)
                if response.status_code != 204:
                    safe_response(response.json())

            return _sdk_call(_close)

        return run_tool(_run)

    @mcp.tool()
    def open_sandbox_port(
        sandbox_id: StrictStr,
        port: SandboxPort,
        confirm: StrictBool,
        allow_public_exposure: StrictBool = False,
    ) -> ToolSuccess:
        """Publicly expose a sandbox port only after explicit exposure approval."""

        def _run() -> Any:
            _guard("open_sandbox_port", confirm, sandbox_id)
            if allow_public_exposure is not True:
                raise ValueError("Public exposure requires allow_public_exposure=true")
            _port(port)
            return _model_result(_sdk_call(lambda: _mutation_api().ports.open(sandbox_id, port)))

        return run_tool(_run)

    @mcp.tool()
    def list_sandbox_ports(sandbox_id: StrictStr) -> ToolSuccess:
        """List the ports exposed by an existing sandbox (read-only)."""

        def _run() -> Any:
            _identifier(sandbox_id)
            return _model_result(
                _sdk_call(lambda: get_session().get_client().sandbox.api.ports.list(sandbox_id))
            )

        return run_tool(_run)

    @mcp.tool()
    def run_sandbox_command(
        sandbox_id: StrictStr,
        command: StrictStr,
        confirm: StrictBool,
        timeout_seconds: TimeoutSeconds = 60,
        cwd: StrictStr | None = None,
        envs: dict[StrictStr, StrictStr] | None = None,
    ) -> ToolSuccess:
        """Run a shell command; every command is a destructive mutation.

        Commands are preserved literally (1-100000 characters); timeout is 1-270
        seconds. Optional cwd and envs are sent only to this command. Request and
        result limit: 1 MiB. Output is redacted, including supplied environment
        values. A timeout does not prove the command stopped; never retry blindly.
        """

        def _run() -> Any:
            _guard("run_sandbox_command", confirm, sandbox_id)
            _timeout(timeout_seconds)
            _command_inputs(command, cwd, envs)
            result = _sdk_call(
                lambda: _mutation_api().commands.run(
                    sandbox_id,
                    command,
                    timeout_seconds=timeout_seconds,
                    cwd=cwd,
                    envs=envs,
                    timeout=timeout_seconds + 10,
                )
            )
            return _model_result(result, tuple((envs or {}).values()))

        return run_tool(_run)
