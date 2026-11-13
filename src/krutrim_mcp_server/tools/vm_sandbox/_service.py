"""Validation and orchestration for the VM Sandbox tools."""

from __future__ import annotations

import ipaddress
import math
import re
import time
import unicodedata
from typing import Any

from krutrim_client import KrutrimClient
from pydantic import BaseModel

VM_SANDBOX_REGIONS = ("In-Hyderabad-1",)
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
    """Reject every region except In-Hyderabad-1 before any VM Sandbox request."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "region must be selected explicitly for this VM Sandbox tool. "
            "VM Sandbox is only available in In-Hyderabad-1."
        )
    if value not in VM_SANDBOX_REGIONS:
        raise ValueError(
            f"VM Sandbox is only available in In-Hyderabad-1; got {value!r}."
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


def _sandbox_api(client: KrutrimClient) -> Any:
    """Native VM Sandbox resources, with client-level retries off for every call."""
    return client.with_options(max_retries=0).sandbox


def _dump(response: Any) -> dict[str, Any]:
    """Return the service envelope exactly as received (code, message, details)."""
    if not isinstance(response, BaseModel):
        raise ValueError("VM Sandbox returned an unexpected response; details withheld")
    return response.model_dump(mode="json", by_alias=True, exclude_unset=True)


def _present(**values: Any) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def list_sandboxes(
    client: KrutrimClient,
    *,
    x_region: str,
    status: str | None = None,
    name: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = validate_pagination(limit=limit, offset=offset)
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
    region = require_region(x_region)
    return _dump(_sandbox_api(client).sandboxes.list(x_region=region, **params))


def retrieve_sandbox(client: KrutrimClient, *, krn_id: str, x_region: str) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    region = require_region(x_region)
    return _dump(_sandbox_api(client).sandboxes.retrieve(krn_id=krn, x_region=region))


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
    region = require_region(x_region)
    checked_flavor = _selectable_flavor_name(client, x_region=region, flavor=flavor)
    return _dump(
        _sandbox_api(client).sandboxes.create(
            x_region=region,
            name=checked_name,
            flavor=checked_flavor,
            idempotency_key=key,
            **_present(
                template=checked_template,
                image=checked_image,
                ttl_seconds=checked_ttl,
                env=encoded_env,
                network=policy,
            ),
        )
    )


def _lifecycle(
    client: KrutrimClient,
    action: str,
    *,
    krn_id: str,
    x_region: str,
    idempotency_key: str | None,
    **extra: Any,
) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    key = validate_idempotency_key(idempotency_key)
    region = require_region(x_region)
    method = getattr(_sandbox_api(client).sandboxes, action)
    return _dump(method(krn_id=krn, x_region=region, idempotency_key=key, **extra))


def delete_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _lifecycle(
        client, "delete", krn_id=krn_id, x_region=x_region, idempotency_key=idempotency_key
    )


def start_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _lifecycle(
        client, "start", krn_id=krn_id, x_region=x_region, idempotency_key=idempotency_key
    )


def stop_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _lifecycle(
        client, "stop", krn_id=krn_id, x_region=x_region, idempotency_key=idempotency_key
    )


def extend_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    ttl_seconds: int,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return _lifecycle(
        client,
        "extend",
        krn_id=krn_id,
        x_region=x_region,
        idempotency_key=idempotency_key,
        ttl_seconds=validate_ttl(ttl_seconds),
    )


def resize_sandbox(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    flavor: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    region = require_region(x_region)
    return _lifecycle(
        client,
        "resize",
        krn_id=krn_id,
        x_region=region,
        idempotency_key=idempotency_key,
        flavor=_selectable_flavor_name(client, x_region=region, flavor=flavor),
    )


def sandbox_usage(client: KrutrimClient, *, krn_id: str, x_region: str) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    region = require_region(x_region)
    return _dump(_sandbox_api(client).sandboxes.usage(krn_id=krn, x_region=region))


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
    krn = validate_identifier(krn_id, "krn_id")
    body = _present(
        cwd=validate_guest_path(cwd, "cwd") if cwd is not None else None,
        env=validate_env(env),
        stdin=validate_stdin(stdin) if stdin is not None else None,
        user=validate_user(user) if user is not None else None,
        timeout_seconds=(
            validate_timeout(timeout_seconds, maximum=120) if timeout_seconds is not None else None
        ),
    )
    checked_cmd = validate_cmd(cmd)
    key = validate_idempotency_key(idempotency_key)
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).sandboxes.exec(
            krn_id=krn, x_region=region, cmd=checked_cmd, idempotency_key=key, **body
        )
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
    krn = validate_identifier(krn_id, "krn_id")
    body = _present(
        cwd=validate_guest_path(cwd, "cwd") if cwd is not None else None,
        env=validate_env(env, reserved_prefixes=("KRUTRIM_",)),
        user=validate_user(user) if user is not None else None,
        timeout_seconds=(
            validate_timeout(timeout_seconds, maximum=604800)
            if timeout_seconds is not None
            else None
        ),
    )
    checked_cmd = validate_cmd(cmd)
    key = validate_idempotency_key(idempotency_key)
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).commands.create(
            krn_id=krn, x_region=region, cmd=checked_cmd, idempotency_key=key, **body
        )
    )


def list_commands(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    page = validate_pagination(limit=limit, offset=offset)
    region = require_region(x_region)
    return _dump(_sandbox_api(client).commands.list(krn_id=krn, x_region=region, **page))


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
    krn = validate_identifier(krn_id, "krn_id")
    command = validate_identifier(command_id, "command_id")
    window = validate_log_window(
        stdout_offset=stdout_offset, stderr_offset=stderr_offset, max_bytes=max_bytes
    )
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).commands.retrieve(
            krn_id=krn, command_id=command, x_region=region, **window
        )
    )


def kill_command(
    client: KrutrimClient,
    *,
    krn_id: str,
    command_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    command = validate_identifier(command_id, "command_id")
    key = validate_idempotency_key(idempotency_key)
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).commands.kill(
            krn_id=krn, command_id=command, x_region=region, idempotency_key=key
        )
    )


def list_flavors(
    client: KrutrimClient,
    *,
    x_region: str,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    page = validate_pagination(limit=limit, offset=offset)
    region = require_region(x_region)
    return _dump(_sandbox_api(client).flavors.list(x_region=region, **page))


def list_templates(
    client: KrutrimClient,
    *,
    x_region: str,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    page = validate_pagination(limit=limit, offset=offset)
    region = require_region(x_region)
    return _dump(_sandbox_api(client).templates.list(x_region=region, **page))


def retrieve_template(client: KrutrimClient, *, template_id: str, x_region: str) -> dict[str, Any]:
    template = validate_identifier(template_id, "template_id")
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).templates.retrieve(template_id=template, x_region=region)
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
    checked_name = validate_template_name(name)
    checked_image = validate_image(image)
    checked_description = validate_description(description) if description is not None else None
    key = validate_idempotency_key(idempotency_key)
    region = require_region(x_region)
    _require_template_capacity(client, x_region=region)
    return _dump(
        _sandbox_api(client).templates.create(
            x_region=region,
            name=checked_name,
            image=checked_image,
            idempotency_key=key,
            **_present(description=checked_description),
        )
    )


def delete_template(
    client: KrutrimClient,
    *,
    template_id: str,
    x_region: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    checked = validate_identifier(template_id, "template_id")
    key = validate_idempotency_key(idempotency_key)
    current = retrieve_template(client, template_id=checked, x_region=x_region)
    details = current.get("details")
    if isinstance(details, dict) and details.get("default_template") is True:
        raise ValueError("platform VM Sandbox templates cannot be deleted")
    return _dump(
        _sandbox_api(client).templates.delete(
            template_id=checked, x_region=require_region(x_region), idempotency_key=key
        )
    )


def retrieve_operation(
    client: KrutrimClient, *, operation_id: str, x_region: str
) -> dict[str, Any]:
    operation = validate_identifier(operation_id, "operation_id")
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).operations.retrieve(operation_id=operation, x_region=region)
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


def retrieve_network(client: KrutrimClient, *, krn_id: str, x_region: str) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    region = require_region(x_region)
    return _dump(_sandbox_api(client).network.retrieve(krn_id=krn, x_region=region))


def update_network(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    network: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    policy = validate_network(network)
    if policy is None:
        raise ValueError("network egress policy is required")
    key = validate_idempotency_key(idempotency_key)
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).network.update(
            krn_id=krn, x_region=region, network=policy, idempotency_key=key
        )
    )


def _checked_port(port: object) -> int:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    return port


def expose_port(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    port: int,
    access: str,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    checked_port = _checked_port(port)
    if access not in {"token", "private"}:
        raise ValueError("access must be token or private")
    key = validate_idempotency_key(idempotency_key)
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).ports.expose(
            krn_id=krn,
            x_region=region,
            port=checked_port,
            access=access,
            idempotency_key=key,
        )
    )


def list_ports(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    page = validate_pagination(limit=limit, offset=offset)
    region = require_region(x_region)
    return _dump(_sandbox_api(client).ports.list(krn_id=krn, x_region=region, **page))


def close_port(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    port: int,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    checked_port = _checked_port(port)
    key = validate_idempotency_key(idempotency_key)
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).ports.close(
            krn_id=krn, port=checked_port, x_region=region, idempotency_key=key
        )
    )


def upload_file(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    path: str,
    content: str,
) -> dict[str, Any]:
    """Write raw bytes. Parent directories must already exist. Never retried."""
    krn = validate_identifier(krn_id, "krn_id")
    checked_path = validate_guest_path(path)
    data = validate_text_file(content)
    region = require_region(x_region)
    return _dump(
        _sandbox_api(client).files.upload(
            krn_id=krn, x_region=region, content=data, path=checked_path
        )
    )


def download_file(
    client: KrutrimClient,
    *,
    krn_id: str,
    x_region: str,
    path: str,
) -> dict[str, Any]:
    krn = validate_identifier(krn_id, "krn_id")
    checked = validate_guest_path(path)
    region = require_region(x_region)
    response = _sandbox_api(client).files.download(krn_id=krn, x_region=region, path=checked)
    content = response.read()
    return {"path": checked, "content": decode_text_file(content), "size_bytes": len(content)}


def create_terminal_ticket(client: KrutrimClient, *, krn_id: str, x_region: str) -> dict[str, Any]:
    """Mint a one-use terminal ticket. Never retried and never sent with an idempotency key."""
    krn = validate_identifier(krn_id, "krn_id")
    region = require_region(x_region)
    return _dump(_sandbox_api(client).terminal.create_ticket(krn_id=krn, x_region=region))


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
