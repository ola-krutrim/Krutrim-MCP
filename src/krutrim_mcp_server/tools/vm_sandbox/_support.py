"""Shared guards, redaction, and error handling for VM Sandbox tools."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any, Literal

from krutrim_client import APIError
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from krutrim_mcp_server.logging_utils import redact_known_secrets
from krutrim_mcp_server.serialize import _is_secret_key, _redact_scalar
from krutrim_mcp_server.tools import CONFIRM_FIELD, ToolSuccess, run_tool
from krutrim_mcp_server.tools.sandbox._responses import redact_secrets

VmSandboxRegion = Annotated[
    Literal["In-Hyderabad-1"],
    Field(
        ...,
        description=(
            "VM Sandbox is only available in In-Hyderabad-1. Pass that region "
            "explicitly. Do not infer it from KRUTRIM_DEFAULT_REGION, and do not "
            "pass In-Bangalore-1."
        ),
    ),
]
VmSandboxID = StrictStr
Confirm = StrictBool
Limit = StrictInt
Offset = StrictInt
IdempotencyKey = StrictStr | None


class VmSandboxEgress(BaseModel):
    """Outbound policy. Allow-only uses deny plus allow; block-list uses allow plus deny."""

    model_config = ConfigDict(extra="forbid")

    default_action: Literal["allow", "deny"]
    allow: list[StrictStr] | None = None
    deny: list[StrictStr] | None = None


class VmSandboxNetwork(BaseModel):
    """Full VM Sandbox egress policy. Omitted lists are left out of the request."""

    model_config = ConfigDict(extra="forbid")

    egress: VmSandboxEgress


def network_body(value: VmSandboxNetwork | dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, BaseModel):
        return value.model_dump()
    if isinstance(value, dict):
        return value
    raise ValueError("network must be an object with an egress policy")

CONFIRM = CONFIRM_FIELD
IDEMPOTENCY_FIELD = Field(
    description=(
        "Optional idempotency key (1-255 printable ASCII characters, no spaces). "
        "Reusing it retries the same mutation instead of starting another one."
    ),
)
_SURFACED_4XX = frozenset({400, 422})
_MAX_DETAIL = 200
_CREDENTIAL_FIELDS = frozenset({"ticket", "url", "proxy_url"})


def run_vm_tool(fn: Callable[[], Any], secrets: tuple[str, ...] = ()) -> ToolSuccess:
    """Execute a VM Sandbox call and withhold unsanitized API bodies."""

    def protected() -> ToolSuccess:
        try:
            payload = fn()
        except APIError as exc:
            status = getattr(exc, "status_code", None)
            detail = f"HTTP {status}" if status is not None else type(exc).__name__
            backend = _validation_detail(exc, secrets)
            if backend is not None:
                raise ValueError(
                    f"VM Sandbox request rejected ({detail}): {backend}. "
                    "Fix the request before retrying."
                ) from None
            raise ValueError(
                f"VM Sandbox request failed ({detail}); response details withheld. "
                "Inspect VM Sandbox state before retrying a mutation."
            ) from None
        return ToolSuccess(data=publish(payload, secrets))

    return run_tool(protected)


def publish(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    """Redact env secrets and accidental credentials, keeping issued tickets and URLs."""
    return _publish(redact_secrets(value, secrets))


def fail_nonzero_exec(payload: dict[str, Any], secrets: tuple[str, ...]) -> dict[str, Any]:
    """HTTP success still carries the command exit code. Nonzero is a failure."""
    details = payload.get("details")
    if not isinstance(details, dict) or type(details.get("exit_code")) is not int:
        raise ValueError("VM Sandbox exec returned an unexpected result; details withheld")
    exit_code = details["exit_code"]
    timed_out = details.get("timed_out") is True
    if exit_code == 0 and not timed_out:
        return payload
    reason = "timed out" if timed_out else f"exit_code {exit_code}"
    stdout = _clip(_public_text(details.get("stdout"), secrets))
    stderr = _clip(_public_text(details.get("stderr"), secrets))
    raise ValueError(
        f"VM Sandbox command failed ({reason}). stdout: {stdout} stderr: {stderr}"
    )


def _public_text(value: object, secrets: tuple[str, ...]) -> str:
    if not isinstance(value, str):
        return ""
    redacted = redact_secrets(value, secrets)
    if not isinstance(redacted, str):
        return ""
    return _redact_scalar(redacted)


def _clip(value: str, limit: int = 400) -> str:
    collapsed = " ".join(value.split())
    if len(collapsed) > limit:
        return collapsed[:limit] + "…"
    return collapsed


def _validation_detail(exc: APIError, secrets: tuple[str, ...]) -> str | None:
    if getattr(exc, "status_code", None) not in _SURFACED_4XX:
        return None
    body = getattr(exc, "body", None)
    message: object = None
    if isinstance(body, dict):
        message = body.get("message") if isinstance(body.get("message"), str) else body.get("error")
    if not isinstance(message, str) or not message.strip():
        return None
    message = _redact_scalar(redact_secrets(message, secrets))
    if not isinstance(message, str):
        return None
    message = " ".join(message.split())
    if len(message) > _MAX_DETAIL:
        message = message[:_MAX_DETAIL] + "…"
    return message


def _publish(value: Any, *, preserve_credential: bool = False) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if preserve_credential:
            return redact_known_secrets(value)
        return _redact_scalar(value)
    if isinstance(value, dict):
        published: dict[str, Any] = {}
        for key, item in value.items():
            text = str(key)
            if _is_secret_key(text):
                published[text] = "***REDACTED***"
            else:
                published[text] = _publish(
                    item,
                    preserve_credential=text in _CREDENTIAL_FIELDS,
                )
        return published
    if isinstance(value, list):
        return [_publish(item) for item in value]
    raise ValueError("VM Sandbox returned an unexpected response; details withheld")
