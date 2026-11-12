"""Direct /sandbox/v1 adapter for VM Sandbox.

Krutrim Cloud now has two sandbox products. The pinned ``krutrim-client`` 0.8.8
client still exposes the original Sandbox API as ``client.sandbox.api`` under
``/omni/sandbox/v1``. The VM Sandbox API lives at ``/sandbox/v1`` and is not in
that client. The staging client that does contain it removes ``sandbox.api``
and the models the existing Sandbox tools import, so this server talks to VM
Sandbox with the same direct-HTTP adapter style as the other SDK gaps.
"""

from __future__ import annotations

import ipaddress
import math
import re
import time
import unicodedata
from typing import Any
from urllib.parse import quote
from uuid import uuid4

import httpx
from krutrim_client import KrutrimClient

from krutrim_mcp_server.config import KNOWN_REGIONS

PREFIX = "/sandbox/v1"
_MAX_FILE_BYTES = 1024 * 1024
_CATALOG_PAGE = 200
_PLATFORM_VCPUS = 4
_PLATFORM_RAM_GIB = 8
_BUILDING_STATUSES = frozenset(
    {
        "building",
        "pending",
        "provisioning",
        "creating",
        "queued",
        "in_progress",
        "build_in_progress",
    }
)
_SANDBOX_STATUSES = frozenset(
    {
        "PROVISIONING",
        "ACTIVE",
        "STOPPING",
        "DOWN",
        "STARTING",
        "RESIZING",
        "DELETING",
        "FAILED",
        "LOST",
    }
)
_ALLOWED_REGISTRIES = frozenset(
    {
        "docker.io",
        "index.docker.io",
        "ghcr.io",
        "quay.io",
        "public.ecr.aws",
        "gcr.io",
        "registry.k8s.io",
        "mcr.microsoft.com",
        "registry.gitlab.com",
    }
)
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_SANDBOX_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?")
_TEMPLATE_NAME = re.compile(r"[a-z][a-z0-9-]{1,39}")
_IMAGE_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_IMAGE_NAME = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
_DIGEST = re.compile(r"sha256:[A-Fa-f0-9]{64}")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}|[0-9]{1,10}")
_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def require_region(value: str) -> str:
    """Reject a missing or unknown region before any VM Sandbox request."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "region must be selected explicitly by the user for this MCP tool call "
            f"(known: {', '.join(KNOWN_REGIONS)})."
        )
    if value not in KNOWN_REGIONS:
        raise ValueError(
            f"unknown region {value!r}; expected one of: {', '.join(KNOWN_REGIONS)}."
        )
    return value


def validate_identifier(value: object, name: str) -> str:
    """Accept a path-safe id or KRN and reject masked account segments."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a non-empty identifier")
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise ValueError(f"{name} must not contain control characters")
    if value in {".", ".."}:
        raise ValueError(f"{name} must not be a dot path segment")
    if ":***:" in value:
        raise ValueError(
            f"{name} contains a masked Krutrim KRN (an account segment redacted as "
            "':***:'). Replace the masked account id with the real account id."
        )
    if any(char in value for char in " /?#\\"):
        raise ValueError(f"{name} must be a path-safe identifier")
    if len(value) > 1024:
        raise ValueError(f"{name} must be at most 1024 characters")
    return value


def validate_sandbox_name(value: object) -> str:
    if not isinstance(value, str) or _SANDBOX_NAME.fullmatch(value) is None:
        raise ValueError(
            "name must be 1..64 letters, digits, '.', '_' or '-', "
            "starting and ending with a letter or digit"
        )
    return value


def validate_template_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or _TEMPLATE_NAME.fullmatch(value) is None
        or value.startswith("img-")
    ):
        raise ValueError(
            "template name must be 2..40 lowercase letters, digits or '-', "
            "start with a letter, and not start with img-"
        )
    return value


def validate_image(value: object) -> str:
    """Allow the public amd64 registries the VM Sandbox console accepts."""
    if not isinstance(value, str) or not 1 <= len(value) <= 255:
        raise ValueError("image must be 1..255 characters")
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "://" in value:
        raise ValueError("image must be a container reference, not a URL")
    reference = value
    if "@" in reference:
        reference, digest = reference.split("@", 1)
        if _DIGEST.fullmatch(digest) is None:
            raise ValueError("image digest must be sha256 and 64 hex characters")
    name = reference
    if ":" in reference:
        name, tag = reference.rsplit(":", 1)
        if _IMAGE_TAG.fullmatch(tag) is None:
            raise ValueError("image tag is invalid")
    parts = name.split("/")
    if not name or not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("image reference is invalid")
    first = parts[0]
    if "." in first or first == "localhost":
        if first.lower() not in _ALLOWED_REGISTRIES:
            raise ValueError(
                "image registry must be Docker Hub, GHCR, Quay, ECR Public, GCR, "
                "registry.k8s.io, MCR, or GitLab"
            )
        path = parts[1:]
        if not path:
            raise ValueError("image reference is missing a name")
    else:
        path = parts
    for part in path:
        if _IMAGE_NAME.fullmatch(part) is None:
            raise ValueError(
                "image name must be lowercase Docker Hub-style path components"
            )
    return value


def validate_description(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("description must be text")
    if len(value.encode()) > 256:
        raise ValueError("description must be at most 256 bytes")
    if any(unicodedata.category(char) == "Cc" and char not in "\n\t" for char in value):
        raise ValueError("description must not contain control characters")
    return value


def validate_ttl(value: object) -> int:
    if type(value) is not int or not 60 <= value <= 604800:
        raise ValueError(
            "ttl_seconds must be an integer from 60 to 604800 (1 minute to 7 days)"
        )
    return value


def validate_timeout(value: object, *, maximum: int, name: str = "timeout_seconds") -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be an integer from 1 to {maximum}")
    return value


def validate_pagination(
    *,
    limit: object = None,
    offset: object = None,
) -> dict[str, int]:
    params: dict[str, int] = {}
    if limit is not None:
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("limit must be an integer from 1 to 200")
        params["limit"] = limit
    if offset is not None:
        if type(offset) is not int or not 0 <= offset <= 2**63 - 1:
            raise ValueError("offset must be an integer from 0 to 2^63-1")
        params["offset"] = offset
    return params


def validate_log_window(
    *,
    stdout_offset: object = None,
    stderr_offset: object = None,
    max_bytes: object = None,
) -> dict[str, int]:
    params: dict[str, int] = {}
    for name, value in (
        ("stdout_offset", stdout_offset),
        ("stderr_offset", stderr_offset),
    ):
        if value is None:
            continue
        if type(value) is not int or not 0 <= value <= 1 << 62:
            raise ValueError(f"{name} must be an integer from 0 to 2^62")
        params[name] = value
    if max_bytes is not None:
        if type(max_bytes) is not int or not 1 <= max_bytes <= _MAX_FILE_BYTES:
            raise ValueError("max_bytes must be an integer from 1 to 1048576")
        params["max_bytes"] = max_bytes
    return params


def validate_env(
    value: object,
    *,
    reserved_prefixes: tuple[str, ...] = (),
) -> dict[str, str] | None:
    """Validate env without echoing names or values in the error."""
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > 64:
        raise ValueError("env must be a mapping of at most 64 variables")
    cleaned: dict[str, str] = {}
    total = 0
    for name, item in value.items():
        if (
            not isinstance(name, str)
            or _ENV_NAME.fullmatch(name) is None
            or not isinstance(item, str)
        ):
            raise ValueError("env must map valid variable names to string values")
        if name.startswith(reserved_prefixes):
            raise ValueError("env variable name uses a reserved prefix")
        total += len(name.encode()) + len(item.encode())
        cleaned[name] = item
    if total > 32768:
        raise ValueError("env must contain at most 32 KiB")
    return cleaned


def validate_destination(value: object) -> str:
    """Accept an IPv4 address, IPv4 CIDR, domain, or *.domain."""
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise ValueError(
            "network destinations must be IPv4 addresses, CIDRs, domains, or *.domains"
        )
    if "://" in value or "?" in value or "#" in value:
        raise ValueError("network destinations must not be URLs")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        if ":" in value or "/" in value:
            raise ValueError(
                "network destinations must be IPv4 addresses, CIDRs, domains, or *.domains"
            ) from None
        domain = value[2:] if value.startswith("*.") else value
        domain = domain[:-1] if domain.endswith(".") else domain
        labels = domain.split(".")
        if (
            not domain
            or len(domain) > 253
            or not labels
            or any(_DOMAIN_LABEL.fullmatch(label) is None for label in labels)
        ):
            raise ValueError(
                "network destinations must be IPv4 addresses, CIDRs, domains, or *.domains"
            )
        return value
    if network.version != 4:
        raise ValueError("IPv6 network rules are not supported")
    return value


def validate_network(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"egress"}:
        raise ValueError("network must be an object with an egress policy")
    egress = value.get("egress")
    if not isinstance(egress, dict):
        raise ValueError("network.egress must be an object")
    allowed_keys = {"default_action", "allow", "deny"}
    if set(egress) - allowed_keys or "default_action" not in egress:
        raise ValueError("network.egress requires default_action and optional allow/deny lists")
    action = egress.get("default_action")
    if action not in {"allow", "deny"}:
        raise ValueError("network.egress.default_action must be allow or deny")
    body: dict[str, Any] = {"default_action": action}
    for field in ("allow", "deny"):
        rules = egress.get(field)
        if rules is None:
            continue
        if not isinstance(rules, list) or len(rules) > 64:
            raise ValueError(f"network.egress.{field} must contain at most 64 destinations")
        body[field] = [validate_destination(rule) for rule in rules]
    return {"egress": body}


def validate_guest_path(value: object, name: str = "path") -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or len(value.encode()) > 4096
    ):
        raise ValueError(f"{name} must be an absolute guest path of at most 4096 bytes")
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise ValueError(f"{name} must not contain control characters")
    parts = value.split("/")
    if any(part in {".", ".."} for part in parts):
        raise ValueError(f"{name} must not contain '.' or '..' segments")
    if any(len(part.encode()) > 255 for part in parts):
        raise ValueError("path components must not exceed 255 bytes")
    return value


def validate_user(value: object) -> str:
    if not isinstance(value, str) or _USER.fullmatch(value) is None:
        raise ValueError("user must be a Linux user name or numeric uid")
    return value


def validate_cmd(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or not 1 <= len(value) <= 100000:
        raise ValueError("cmd must contain 1 to 100000 non-blank characters")
    return value


def validate_stdin(value: object) -> str:
    if not isinstance(value, str) or len(value.encode()) > _MAX_FILE_BYTES:
        raise ValueError("stdin must be a string of at most 1 MiB")
    return value


def validate_idempotency_key(value: object) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 255
        or any(not 33 <= ord(char) <= 126 for char in value)
    ):
        raise ValueError(
            "idempotency_key must contain 1..255 printable ASCII characters without spaces"
        )
    return value


def validate_text_file(value: object) -> bytes:
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("content must be text without NUL")
    encoded = value.encode("utf-8")
    if len(encoded) > _MAX_FILE_BYTES:
        raise ValueError("content exceeds the 1 MiB limit")
    return encoded


def decode_text_file(content: bytes) -> str:
    if len(content) > _MAX_FILE_BYTES:
        raise ValueError("VM Sandbox file exceeds the 1 MiB limit; response withheld")
    if b"\x00" in content:
        raise ValueError("VM Sandbox file is binary; response withheld")
    try:
        return content.decode("utf-8")
    except UnicodeError:
        raise ValueError("VM Sandbox file is not UTF-8 text; response withheld") from None


def _positive_seconds(value: object, name: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    if not math.isfinite(value) or not minimum <= float(value) <= maximum:
        raise ValueError(f"{name} must be from {minimum:g} to {maximum:g} seconds")
    return float(value)


def _request(
    client: KrutrimClient,
    method: str,
    path: str,
    *,
    x_region: str,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    content: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    idempotency_key: str | None = None,
    send_idempotency: bool = False,
) -> Any:
    region = require_region(x_region)
    headers = {"x-region": region, **(extra_headers or {})}
    if send_idempotency:
        headers["Idempotency-Key"] = idempotency_key or str(uuid4())
    options: dict[str, Any] = {"headers": headers, "max_retries": 0}
    if params:
        options["params"] = params
    if content is not None:
        options["content"] = content
    api = client.with_options(max_retries=0)
    if method == "get":
        response = api.get(path, cast_to=httpx.Response, options=options)
    elif method == "post":
        response = api.post(path, cast_to=httpx.Response, body=json_body, options=options)
    elif method == "put":
        response = api.put(path, cast_to=httpx.Response, body=json_body, options=options)
    elif method == "delete":
        response = api.delete(path, cast_to=httpx.Response, body=json_body, options=options)
    else:
        raise ValueError(f"unsupported VM Sandbox method {method}")
    return _json_object(response)


def _json_object(response: httpx.Response) -> dict[str, Any]:
    if response.status_code >= 400:
        raise ValueError(
            f"VM Sandbox request failed (HTTP {response.status_code}); "
            "response details withheld"
        )
    if not response.content:
        return {"status_code": response.status_code, "accepted": True}
    try:
        payload = response.json()
    except ValueError:
        raise ValueError("VM Sandbox returned a non-JSON response; details withheld") from None
    if not isinstance(payload, dict):
        raise ValueError("VM Sandbox returned an unexpected response; details withheld")
    return payload


def _resource_path(kind: str, *segments: str) -> str:
    encoded = "/".join(
        quote(validate_identifier(segment, "identifier"), safe=":") for segment in segments
    )
    return f"{PREFIX}/{kind}/{encoded}" if encoded else f"{PREFIX}/{kind}"


def _sandbox_path(krn_id: str, *suffix: str) -> str:
    return _resource_path("sandboxes", krn_id, *suffix)


def list_sandboxes(
    client: KrutrimClient,
    *,
    x_region: str,
    status: str | None = None,
    name: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    params = validate_pagination(limit=limit, offset=offset)
    if status is not None:
        if status not in _SANDBOX_STATUSES:
            raise ValueError("status must be a VM Sandbox lifecycle status")
        params["status"] = status
    if name is not None:
        if not isinstance(name, str) or not name.strip() or len(name) > 64:
            raise ValueError("name filter must be 1..64 non-blank characters")
        if any(unicodedata.category(char) == "Cc" for char in name):
            raise ValueError("name filter must not contain control characters")
        params["name"] = name
    return _request(client, "get", f"{PREFIX}/sandboxes", x_region=x_region, params=params)


def retrieve_sandbox(
    client: KrutrimClient, *, krn_id: str, x_region: str
) -> dict[str, Any]:
    return _request(client, "get", _sandbox_path(krn_id), x_region=x_region)


def create_sandbox(
    client: KrutrimClient,
    *,
    x_region: str,
    name: str,
    flavor: str,
    template: str | None = None,
    image: str | None = None,
    ttl_seconds: int | None = None,
    env: dict[str, str] | None = None,
    network: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    checked_name = validate_sandbox_name(name)
    if template is not None and image is not None:
        raise ValueError("Pass template or image, not both")
    checked_template = validate_identifier(template, "template") if template is not None else None
    checked_image = validate_image(image) if image is not None else None
    checked_ttl = validate_ttl(ttl_seconds) if ttl_seconds is not None else None
    encoded_env = validate_env(env, reserved_prefixes=("KRUTRIM_", "SPACE_"))
    policy = validate_network(network)
    key = validate_idempotency_key(idempotency_key)
    body: dict[str, Any] = {
        "name": checked_name,
        "flavor": _selectable_flavor_name(client, x_region=x_region, flavor=flavor),
    }
    if checked_template is not None:
        body["template"] = checked_template
    if checked_image is not None:
        body["image"] = checked_image
    if checked_ttl is not None:
        body["ttl_seconds"] = checked_ttl
    if encoded_env is not None:
        body["env"] = encoded_env
    if policy is not None:
        body["network"] = policy
    return _request(
        client,
        "post",
        f"{PREFIX}/sandboxes",
        x_region=x_region,
        json_body=body,
        idempotency_key=key,
        send_idempotency=True,
    )


def delete_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "delete",
        _sandbox_path(krn_id),
        x_region=x_region,
        json_body={},
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def start_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "post",
        _sandbox_path(krn_id, "start"),
        x_region=x_region,
        json_body={},
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def stop_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "post",
        _sandbox_path(krn_id, "stop"),
        x_region=x_region,
        json_body={},
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def extend_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    ttl_seconds: int,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "post",
        _sandbox_path(krn_id, "extend"),
        x_region=x_region,
        json_body={"ttl_seconds": validate_ttl(ttl_seconds)},
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def resize_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    flavor: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "post",
        _sandbox_path(krn_id, "resize"),
        x_region=x_region,
        json_body={"flavor": _selectable_flavor_name(client, x_region=x_region, flavor=flavor)},
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def sandbox_usage(
    client: KrutrimClient, *, krn_id: str, x_region: str
) -> dict[str, Any]:
    return _request(client, "get", _sandbox_path(krn_id, "usage"), x_region=x_region)


def exec_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    cmd: str,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
    user: str | None = None,
    timeout_seconds: int | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"cmd": validate_cmd(cmd)}
    if cwd is not None:
        body["cwd"] = validate_guest_path(cwd, "cwd")
    encoded_env = validate_env(env)
    if encoded_env is not None:
        body["env"] = encoded_env
    if stdin is not None:
        body["stdin"] = validate_stdin(stdin)
    if user is not None:
        body["user"] = validate_user(user)
    if timeout_seconds is not None:
        body["timeout_seconds"] = validate_timeout(timeout_seconds, maximum=120)
    return _request(
        client,
        "post",
        _sandbox_path(krn_id, "exec"),
        x_region=x_region,
        json_body=body,
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def create_command(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    cmd: str,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    user: str | None = None,
    timeout_seconds: int | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"cmd": validate_cmd(cmd)}
    if cwd is not None:
        body["cwd"] = validate_guest_path(cwd, "cwd")
    encoded_env = validate_env(env, reserved_prefixes=("KRUTRIM_",))
    if encoded_env is not None:
        body["env"] = encoded_env
    if user is not None:
        body["user"] = validate_user(user)
    if timeout_seconds is not None:
        body["timeout_seconds"] = validate_timeout(timeout_seconds, maximum=604800)
    return _request(
        client,
        "post",
        _sandbox_path(krn_id, "commands"),
        x_region=x_region,
        json_body=body,
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def list_commands(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "get",
        _sandbox_path(krn_id, "commands"),
        x_region=x_region,
        params=validate_pagination(limit=limit, offset=offset),
    )


def retrieve_command(
    client: KrutrimClient,
    *,
    krn_id: str,
    command_id: str,
    x_region: str,
    stdout_offset: int | None = None,
    stderr_offset: int | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "get",
        _sandbox_path(krn_id, "commands", validate_identifier(command_id, "command_id")),
        x_region=x_region,
        params=validate_log_window(
            stdout_offset=stdout_offset,
            stderr_offset=stderr_offset,
            max_bytes=max_bytes,
        ),
    )


def kill_command(
    client: KrutrimClient,
    *,
    krn_id: str,
    command_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "post",
        _sandbox_path(
            krn_id,
            "commands",
            validate_identifier(command_id, "command_id"),
            "kill",
        ),
        x_region=x_region,
        json_body={},
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def list_flavors(
    client: KrutrimClient,
    *,
    x_region: str,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "get",
        f"{PREFIX}/flavors",
        x_region=x_region,
        params=validate_pagination(limit=limit, offset=offset),
    )


def list_templates(
    client: KrutrimClient,
    *,
    x_region: str,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "get",
        f"{PREFIX}/templates",
        x_region=x_region,
        params=validate_pagination(limit=limit, offset=offset),
    )


def retrieve_template(
    client: KrutrimClient, *, template_id: str, x_region: str
) -> dict[str, Any]:
    return _request(
        client,
        "get",
        _resource_path("templates", validate_identifier(template_id, "template_id")),
        x_region=x_region,
    )


def create_template(
    client: KrutrimClient,
    *,
    x_region: str,
    name: str,
    image: str,
    description: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": validate_template_name(name),
        "image": validate_image(image),
    }
    if description is not None:
        body["description"] = validate_description(description)
    key = validate_idempotency_key(idempotency_key)
    _require_template_capacity(client, x_region=x_region)
    return _request(
        client,
        "post",
        f"{PREFIX}/templates",
        x_region=x_region,
        json_body=body,
        idempotency_key=key,
        send_idempotency=True,
    )


def delete_template(
    client: KrutrimClient,
    *,
    template_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    checked = validate_identifier(template_id, "template_id")
    current = retrieve_template(client, template_id=checked, x_region=x_region)
    details = current.get("details")
    if isinstance(details, dict) and details.get("default_template") is True:
        raise ValueError("platform VM Sandbox templates cannot be deleted")
    return _request(
        client,
        "delete",
        _resource_path("templates", checked),
        x_region=x_region,
        json_body={},
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def retrieve_operation(
    client: KrutrimClient, *, operation_id: str, x_region: str
) -> dict[str, Any]:
    return _request(
        client,
        "get",
        _resource_path("operations", validate_identifier(operation_id, "operation_id")),
        x_region=x_region,
    )


def wait_operation(
    client: KrutrimClient,
    *,
    operation_id: str,
    x_region: str,
    timeout_seconds: float = 120,
    poll_interval_seconds: float = 2,
) -> dict[str, Any]:
    """Poll until the operation succeeds or fails. Timing out does not cancel it."""
    checked = validate_identifier(operation_id, "operation_id")
    region = require_region(x_region)
    deadline_seconds = _positive_seconds(
        timeout_seconds, "timeout_seconds", minimum=1, maximum=600
    )
    interval = _positive_seconds(
        poll_interval_seconds, "poll_interval_seconds", minimum=0.5, maximum=60
    )
    deadline = time.monotonic() + deadline_seconds
    last_state = "unknown"
    while True:
        if time.monotonic() >= deadline:
            raise ValueError(
                f"VM Sandbox operation {checked} was still {last_state} when the wait "
                "timed out. The server operation was not cancelled. Use "
                "get_vm_sandbox_operation to check it."
            )
        payload = retrieve_operation(client, operation_id=checked, x_region=region)
        details = payload.get("details")
        state = details.get("state") if isinstance(details, dict) else None
        if state == "succeeded":
            return payload
        if state == "failed":
            error = details.get("error") if isinstance(details, dict) else None
            detail = error.strip() if isinstance(error, str) and error.strip() else "no error text"
            if len(detail) > 200:
                detail = detail[:200] + "…"
            raise ValueError(
                f"VM Sandbox operation {checked} failed ({detail}). "
                "Inspect the VM Sandbox before retrying."
            )
        if state not in {"pending", "running"}:
            raise ValueError("VM Sandbox operation returned an unexpected state; details withheld")
        last_state = state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            continue
        time.sleep(min(interval, remaining))


def retrieve_network(
    client: KrutrimClient, *, krn_id: str, x_region: str
) -> dict[str, Any]:
    return _request(client, "get", _sandbox_path(krn_id, "network"), x_region=x_region)


def update_network(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    network: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    policy = validate_network(network)
    if policy is None:
        raise ValueError("network egress policy is required")
    return _request(
        client,
        "put",
        _sandbox_path(krn_id, "network"),
        x_region=x_region,
        json_body=policy,
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def expose_port(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    port: int,
    access: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    if access not in {"token", "private"}:
        raise ValueError("access must be token or private")
    return _request(
        client,
        "post",
        _sandbox_path(krn_id, "ports"),
        x_region=x_region,
        json_body={"port": port, "access": access},
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def list_ports(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    return _request(
        client,
        "get",
        _sandbox_path(krn_id, "ports"),
        x_region=x_region,
        params=validate_pagination(limit=limit, offset=offset),
    )


def close_port(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    port: int,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    return _request(
        client,
        "delete",
        f"{_sandbox_path(krn_id, 'ports')}/{port}",
        x_region=x_region,
        json_body={},
        idempotency_key=validate_idempotency_key(idempotency_key),
        send_idempotency=True,
    )


def upload_file(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    path: str,
    content: str,
) -> dict[str, Any]:
    """PUT raw bytes. Parent directories must already exist. Retries stay off."""
    return _request(
        client,
        "put",
        _sandbox_path(krn_id, "files"),
        x_region=x_region,
        content=validate_text_file(content),
        params={"path": validate_guest_path(path)},
        extra_headers={"Content-Type": "application/octet-stream"},
    )


def download_file(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    path: str,
) -> dict[str, Any]:
    checked = validate_guest_path(path)
    region = require_region(x_region)
    options = {
        "headers": {"x-region": region},
        "params": {"path": checked},
        "max_retries": 0,
    }
    response = client.with_options(max_retries=0).get(
        _sandbox_path(krn_id, "files"),
        cast_to=httpx.Response,
        options=options,
    )
    if response.status_code >= 400:
        raise ValueError(
            f"VM Sandbox file request failed (HTTP {response.status_code}); "
            "response omitted to protect file content"
        )
    text = decode_text_file(response.content)
    return {"path": checked, "content": text, "size_bytes": len(response.content)}


def create_terminal_ticket(
    client: KrutrimClient, *, krn_id: str, x_region: str
) -> dict[str, Any]:
    """Mint a one-use terminal ticket. No idempotency key; retries stay off."""
    return _request(
        client,
        "post",
        _sandbox_path(krn_id, "terminal", "ticket"),
        x_region=x_region,
        json_body={},
    )


def _catalog_items(
    client: KrutrimClient,
    *,
    x_region: str,
    kind: str,
    item_key: str,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    offset = 0
    while True:
        if kind == "flavors":
            payload = list_flavors(client, x_region=x_region, limit=_CATALOG_PAGE, offset=offset)
        else:
            payload = list_templates(client, x_region=x_region, limit=_CATALOG_PAGE, offset=offset)
        details = payload.get("details")
        if not isinstance(details, dict):
            raise ValueError(f"VM Sandbox {kind} catalog was malformed; request blocked")
        page = details.get(item_key)
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            raise ValueError(f"VM Sandbox {kind} catalog was malformed; request blocked")
        items.extend(page)
        total = details.get("total")
        offset += len(page)
        if not page or len(page) < _CATALOG_PAGE or (type(total) is int and offset >= total):
            return items
        if offset > 10000:
            raise ValueError(f"VM Sandbox {kind} catalog was too large; request blocked")


def _selectable_flavor_name(client: KrutrimClient, *, x_region: str, flavor: object) -> str:
    if not isinstance(flavor, str) or not flavor.strip() or flavor != flavor.strip():
        raise ValueError("flavor must be the exact name returned by list_vm_sandbox_flavors")
    flavors = _catalog_items(client, x_region=x_region, kind="flavors", item_key="flavors")
    selected = [item for item in flavors if item.get("name") == flavor]
    if len(selected) != 1:
        names = sorted(
            {item.get("name") for item in flavors if isinstance(item.get("name"), str)}
        )
        shown = ", ".join(names[:20]) or "(none listed)"
        raise ValueError(
            f"VM Sandbox flavor {flavor!r} is missing or ambiguous in region {x_region}. "
            f"Choose an exact name from list_vm_sandbox_flavors: {shown}."
        )
    item = selected[0]
    if _exceeds(item.get("vcpus"), _PLATFORM_VCPUS):
        raise ValueError(
            f"VM Sandbox flavor {flavor!r} exceeds the platform limit of "
            f"{_PLATFORM_VCPUS} vCPU"
        )
    if _exceeds(item.get("ram_gib"), _PLATFORM_RAM_GIB):
        raise ValueError(
            f"VM Sandbox flavor {flavor!r} exceeds the platform limit of "
            f"{_PLATFORM_RAM_GIB} GiB"
        )
    return flavor


def _exceeds(value: object, limit: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if not math.isfinite(value):
        raise ValueError("VM Sandbox flavor catalog was malformed; request blocked")
    return float(value) > limit


def _is_custom_template(item: dict[str, Any]) -> bool:
    if item.get("custom") is True:
        return True
    if item.get("custom") is False or item.get("default_template") is True:
        return False
    return False


def _require_template_capacity(client: KrutrimClient, *, x_region: str) -> None:
    templates = _catalog_items(client, x_region=x_region, kind="templates", item_key="templates")
    custom = [item for item in templates if _is_custom_template(item)]
    if len(custom) >= 10:
        raise ValueError(
            "VM Sandbox allows 10 custom templates. Delete one before building another."
        )
    building = [
        item
        for item in custom
        if str(item.get("status", "")).strip().lower() in _BUILDING_STATUSES
    ]
    if len(building) >= 2:
        raise ValueError("VM Sandbox allows 2 concurrent template builds.")
