"""Serialize client responses into JSON-friendly structures for MCP tool results."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import fields, is_dataclass
from typing import Any

from jsonschema import Draft202012Validator
from mcp.types import CallToolResult
from pydantic import AnyUrl, BaseModel, TypeAdapter, ValidationError

from krutrim_mcp_server.logging_utils import redact_known_secrets, redact_known_uri_secrets

_SECRET_KEY_PATTERN = re.compile(
    r"^(?:api[_-]?key|password|secret|secret[_-]?(?:key|access[_-]?key)|"
    r"token|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
    r"client[_-]?secret(?:[_-]?value)?|authorization|private[_-]?key|"
    r"credentials?|kube[_-]?config|user[_-]?data|environment[_-]?variables)$",
    re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(r"\bBearer\s+\S+", re.IGNORECASE)
_JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_REDACTED = "***REDACTED***"


def _is_secret_key(key: Any) -> bool:
    return bool(_SECRET_KEY_PATTERN.fullmatch(str(key).strip()))


def _redact_scalar(value: str) -> str:
    if _PRIVATE_KEY_PATTERN.search(value):
        return _REDACTED
    redacted = redact_known_secrets(value)
    redacted = _BEARER_PATTERN.sub("Bearer ***REDACTED***", redacted)
    return _JWT_PATTERN.sub(_REDACTED, redacted)


# Only this installed MCP schema confers protocol privileges. Never derive a
# preservation schema from a tool payload's models, aliases, or Literal fields.
_PROTOCOL_SCHEMA = CallToolResult.model_json_schema()
_PROTOCOL_VALIDATOR = Draft202012Validator(_PROTOCOL_SCHEMA)
_RESULT_ADAPTER = TypeAdapter(CallToolResult)
_KEY_ADAPTER = TypeAdapter(dict[Any, None])


class _JSONObjectPairs(list):
    """Keep JSON objects distinct from arrays without discarding duplicate keys."""


class _URIString(str):
    """A JSON string whose Python source was URI-typed, not ordinary text."""


class _AmbiguousMappingKey(ValueError):
    """A lossy redaction must not be retried using a fallback representation."""


def _unique_mapping(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _AmbiguousMappingKey("Ambiguous JSON mapping key")
        result[key] = value
    return result


def _redact_uri_sources(value: Any) -> Any:
    """Sanitize typed URIs on a copy *before* user serializers erase their type.

    JSON-only serializers can move a URI into a list or mapping key, or emit an
    ordinary string instead. Matching Python/JSON paths cannot establish their
    provenance. Give those serializers sanitized URI inputs, leaving all plain
    strings alone and still letting Pydantic own JSON-mode output semantics.
    """
    replacements: dict[int, Any] = {}
    seen: set[int] = set()

    def collect(item: Any) -> None:
        if id(item) in seen:
            return
        seen.add(id(item))
        if isinstance(item, AnyUrl):
            redacted = _redact_json(_URIString(str(item)), {})
            if redacted != str(item):
                replacements[id(item)] = type(item)(redacted)
        elif isinstance(item, BaseModel):
            collect(item.__dict__)
            collect(item.__pydantic_extra__)
            collect(item.__pydantic_private__)
        elif is_dataclass(item) and not isinstance(item, type):
            for field in fields(item):
                collect(getattr(item, field.name, None))
        elif isinstance(item, dict):
            for key, child in item.items():
                collect(key)
                collect(child)
        elif isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                collect(child)

    collect(value)
    # Preserve container/model types and shared references seen by serializers;
    # reconstructing them with type(value)(items) breaks namedtuples, for example.
    return deepcopy(value, replacements) if replacements else value


def _check_json_shape(original: Any, sanitized: Any) -> None:
    """Reject lossy or shape-dependent serializers after sanitizing URI inputs.

    In particular, a serializer can build a dict keyed by its URI argument. Two
    distinct inputs may then collapse *inside* that serializer, before Pydantic
    can emit duplicate JSON entries. Compare the unmodified JSON shape as well.
    """
    if isinstance(original, list):
        if type(original) is not type(sanitized) or len(original) != len(sanitized):
            raise _AmbiguousMappingKey("Ambiguous JSON serializer shape")
        if isinstance(original, _JSONObjectPairs):
            if len({key for key, _ in original}) != len(original):
                raise _AmbiguousMappingKey("Ambiguous JSON mapping key")
            for (_, before), (_, after) in zip(original, sanitized):
                _check_json_shape(before, after)
        else:
            for before, after in zip(original, sanitized):
                _check_json_shape(before, after)
    elif type(original) is not type(sanitized):
        raise _AmbiguousMappingKey("Ambiguous JSON serializer shape")


def _json_snapshot(value: Any, adapter: TypeAdapter, *, by_alias: bool | None = None) -> Any:
    original = json.loads(
        adapter.dump_json(value, by_alias=by_alias, warnings=False),
        object_pairs_hook=_JSONObjectPairs,
    )
    sanitized = _redact_uri_sources(value)
    source = adapter.dump_python(sanitized, by_alias=by_alias, warnings=False)
    pairs = original if sanitized is value else json.loads(
        adapter.dump_json(sanitized, by_alias=by_alias, warnings=False),
        object_pairs_hook=_JSONObjectPairs,
    )
    _check_json_shape(original, pairs)
    return _normalize_json_pairs(pairs, source)


def _normalize_json_pairs(value: Any, source: Any) -> Any:
    """Materialize JSON objects only after checking key provenance and collisions.

    Pydantic's JSON byte serializer retains duplicate object entries, whereas
    dump_python(mode='json') silently overwrites them. Keep those entries paired
    until this walk. The Python snapshot distinguishes None from literal 'None';
    normalize each ancestor key with Pydantic before looking up its child, rather
    than guessing a source key from its string representation. Ambiguous keys
    fail closed at the outer MCP boundary, never selecting an overwritten value.
    """
    if isinstance(value, _JSONObjectPairs):
        sources = {}
        if isinstance(source, dict):
            for original_key, original_value in source.items():
                json_key = next(iter(_KEY_ADAPTER.dump_python(
                    {original_key: None}, mode="json", warnings=False,
                )))
                if json_key in sources:
                    raise _AmbiguousMappingKey("Ambiguous JSON mapping key")
                sources[json_key] = (original_key, original_value)
        normalized = {}
        seen = set()
        for key, item in value:
            original_key, original = sources.get(key, (key, None))
            output_key = "null" if original_key is None else key
            if isinstance(original_key, AnyUrl):
                output_key = _URIString(output_key)
            if key in seen or output_key in normalized:
                raise _AmbiguousMappingKey("Ambiguous JSON mapping key")
            seen.add(key)
            normalized[output_key] = _normalize_json_pairs(item, original)
        return normalized
    if isinstance(value, list):
        originals = iter(source) if isinstance(source, (list, tuple, set, frozenset)) else iter(())
        return [_normalize_json_pairs(item, next(originals, None)) for item in value]
    if isinstance(value, str) and isinstance(source, AnyUrl) and value == str(source):
        return _URIString(value)
    return value


def _redact_json(value: Any, schema: dict[str, Any]) -> Any:
    """Walk normalized JSON; schema privileges stop at arbitrary data/metadata."""
    if "$ref" in schema:
        schema = _PROTOCOL_SCHEMA["$defs"][schema["$ref"].removeprefix("#/$defs/")]
    if "anyOf" in schema:
        schema = next(
            (branch for branch in schema["anyOf"]
             if _PROTOCOL_VALIDATOR.evolve(schema=branch).is_valid(value)),
            {},
        )
        return _redact_json(value, schema)
    if "const" in schema or "enum" in schema:
        return value
    if isinstance(value, dict):
        fields = schema.get("properties", {})
        return _unique_mapping(
            (key if key in fields else _redact_json(key, {}),
             _redact_json(item, fields.get(key, {})))
            for key, item in value.items()
        )
    if isinstance(value, list):
        return [_redact_json(item, schema.get("items", {})) for item in value]
    if isinstance(value, str):
        redacted = redact_known_secrets(value)
        if isinstance(value, _URIString) or schema.get("format") == "uri":
            try:
                return str(AnyUrl(redact_known_uri_secrets(value)))
            except ValidationError:
                # A credential may occupy the URI's scheme, port, or entire value.
                return "redacted:***REDACTED***"
        return redacted
    return value


def redact_tool_result(
    result: CallToolResult, *, output_fields: frozenset[str] = frozenset(),
) -> CallToolResult:
    """Normalize first, redact JSON, then rebuild a plain, valid protocol result.

    Pydantic owns conversion of arbitrary payload types and mapping keys. Suppress
    serializer warnings because their reflected values may themselves be secrets.
    """
    payload = _json_snapshot(result, _RESULT_ADAPTER, by_alias=True)
    schema = _PROTOCOL_SCHEMA
    if output_fields:
        # Apply envelope privileges on the first pass; redacting then restoring
        # fields can create a collision that the actual output would not have.
        schema = {**schema, "properties": {
            **schema["properties"],
            "structuredContent": {"properties": {name: {} for name in output_fields}},
        }}
    redacted = _redact_json(payload, schema)
    if payload.get("structuredContent") is not None and output_fields:
        # FastMCP also emits a JSON text copy of structured output. Compare the
        # normalized representations and preserve envelope keys only in mirrors.
        for original, copied in zip(payload["content"], redacted["content"]):
            if original.get("type") == "text":
                try:
                    mirrored = json.loads(original["text"]) == payload["structuredContent"]
                except ValueError:
                    mirrored = False
                if mirrored:
                    copied["text"] = json.dumps(redacted["structuredContent"], indent=2)
    return CallToolResult.model_validate(redacted)


def to_jsonable(value: Any) -> Any:
    """Convert client / Pydantic / httpx responses into plain JSON-serializable data."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_scalar(value)

    if isinstance(value, dict):
        return _unique_mapping(
            (_redact_scalar(str(k)), _REDACTED if _is_secret_key(k) else to_jsonable(v))
            for k, v in value.items()
        )

    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]

    # Pydantic serializer warnings can include reflected credentials.
    if isinstance(value, BaseModel):
        return to_jsonable(_json_snapshot(value, TypeAdapter(type(value))))

    # Pydantic-like response objects
    if hasattr(value, "model_dump"):
        try:
            return to_jsonable(value.model_dump(mode="json"))
        except TypeError:
            return to_jsonable(value.model_dump())

    # Pydantic v1
    if hasattr(value, "dict"):
        try:
            return to_jsonable(value.dict())
        except _AmbiguousMappingKey:
            raise
        except Exception:
            pass

    # httpx.Response
    if hasattr(value, "json") and hasattr(value, "status_code"):
        try:
            return to_jsonable({"status_code": value.status_code, "body": value.json()})
        except _AmbiguousMappingKey:
            raise
        except Exception:
            try:
                return to_jsonable({"status_code": value.status_code, "body": value.text})
            except _AmbiguousMappingKey:
                raise
            except Exception:
                return {"status_code": getattr(value, "status_code", None)}

    if hasattr(value, "to_dict"):
        try:
            return to_jsonable(value.to_dict())
        except _AmbiguousMappingKey:
            raise
        except Exception:
            pass

    # Fallback: best-effort string
    try:
        return to_jsonable(json.loads(json.dumps(value, default=str)))
    except _AmbiguousMappingKey:
        raise
    except Exception:
        return _redact_scalar(str(value))
