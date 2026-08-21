"""Recipient-encrypted delivery for credentials created through MCP tools."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

PUBLIC_KEY_PREFIX = "kmcp-pub-v1:"
PRIVATE_KEY_PREFIX = "kmcp-priv-v1:"
KEY_FILE_FORMAT = "krutrim-mcp-recipient-key-v1"
BUNDLE_FORMAT = "krutrim-mcp-encrypted-credential-bundle"
PAYLOAD_FORMAT = "krutrim-mcp-credential-payload"
BUNDLE_VERSION = 1
ALGORITHM = "libsodium-sealed-box-x25519-xsalsa20-poly1305"


class CredentialDeliveryError(ValueError):
    """Raised when a recipient key or encrypted credential bundle is invalid."""


@dataclass(frozen=True)
class RecipientPublicKey:
    """Validated recipient public key and its confirmation fingerprint."""

    key: PublicKey
    encoded: str
    fingerprint: str


@dataclass(frozen=True)
class RecipientPrivateKey:
    """Validated local private key and derived public identity."""

    key: PrivateKey
    public_key: str
    fingerprint: str


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str, *, field_name: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise CredentialDeliveryError(f"{field_name} must be a non-empty string")
    encoded = value.strip()
    try:
        decoded = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, TypeError) as exc:
        raise CredentialDeliveryError(f"{field_name} is not valid base64url") from exc
    if _b64url_encode(decoded) != encoded.rstrip("="):
        raise CredentialDeliveryError(f"{field_name} is not canonical base64url")
    return decoded


def _encode_public_key(key: PublicKey) -> str:
    return f"{PUBLIC_KEY_PREFIX}{_b64url_encode(bytes(key))}"


def _fingerprint(key: PublicKey) -> str:
    return f"sha256:{hashlib.sha256(bytes(key)).hexdigest()}"


def parse_recipient_public_key(
    value: str,
    *,
    expected_fingerprint: str,
) -> RecipientPublicKey:
    """Validate a public key and its independently confirmed fingerprint."""
    if not isinstance(value, str) or not value.startswith(PUBLIC_KEY_PREFIX):
        raise CredentialDeliveryError(
            f"recipient_public_key must use the {PUBLIC_KEY_PREFIX!r} format"
        )
    raw = _b64url_decode(
        value[len(PUBLIC_KEY_PREFIX) :],
        field_name="recipient_public_key",
    )
    if len(raw) != PublicKey.SIZE:
        raise CredentialDeliveryError(
            f"recipient_public_key must contain exactly {PublicKey.SIZE} bytes"
        )
    public_key = PublicKey(raw)
    fingerprint = _fingerprint(public_key)
    if not isinstance(expected_fingerprint, str):
        raise CredentialDeliveryError("recipient_key_fingerprint must be a non-empty string")
    supplied = expected_fingerprint.strip().lower()
    if not secrets.compare_digest(fingerprint, supplied):
        raise CredentialDeliveryError(
            "recipient_key_fingerprint does not match recipient_public_key"
        )
    return RecipientPublicKey(
        key=public_key,
        encoded=_encode_public_key(public_key),
        fingerprint=fingerprint,
    )


def generate_recipient_key_file(path: str | os.PathLike[str]) -> dict[str, str]:
    """Generate a recipient key pair and write its private material owner-only."""
    destination = Path(path).expanduser()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    private_key = PrivateKey.generate()
    public_key = _encode_public_key(private_key.public_key)
    fingerprint = _fingerprint(private_key.public_key)
    document = {
        "format": KEY_FILE_FORMAT,
        "private_key": f"{PRIVATE_KEY_PREFIX}{_b64url_encode(bytes(private_key))}",
        "public_key": public_key,
        "fingerprint": fingerprint,
    }

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(destination, flags, 0o600)
    except FileExistsError as exc:
        raise CredentialDeliveryError(f"private key file already exists: {destination}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    os.chmod(destination, 0o600)
    return {
        "private_key_file": str(destination),
        "public_key": public_key,
        "fingerprint": fingerprint,
    }


def load_recipient_private_key(path: str | os.PathLike[str]) -> RecipientPrivateKey:
    """Load a local private key after enforcing owner-only file permissions."""
    source = Path(path).expanduser()
    try:
        file_stat = source.stat()
    except FileNotFoundError as exc:
        raise CredentialDeliveryError(f"private key file does not exist: {source}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise CredentialDeliveryError(f"private key path must be a regular file: {source}")
    if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
        raise CredentialDeliveryError(
            f"private key file must be owned by the current user: {source}"
        )
    mode = stat.S_IMODE(file_stat.st_mode)
    if mode & 0o077:
        raise CredentialDeliveryError(
            f"private key file must not be accessible by group or others: {source}"
        )
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CredentialDeliveryError(f"private key file is not valid JSON: {source}") from exc
    if not isinstance(document, dict) or document.get("format") != KEY_FILE_FORMAT:
        raise CredentialDeliveryError(f"private key file has an unsupported format: {source}")

    encoded = document.get("private_key")
    if not isinstance(encoded, str) or not encoded.startswith(PRIVATE_KEY_PREFIX):
        raise CredentialDeliveryError(f"private key file is missing its private key: {source}")
    raw = _b64url_decode(
        encoded[len(PRIVATE_KEY_PREFIX) :],
        field_name="private_key",
    )
    if len(raw) != PrivateKey.SIZE:
        raise CredentialDeliveryError(f"private_key must contain exactly {PrivateKey.SIZE} bytes")
    private_key = PrivateKey(raw)
    public_key = _encode_public_key(private_key.public_key)
    fingerprint = _fingerprint(private_key.public_key)
    if document.get("public_key") != public_key or document.get("fingerprint") != fingerprint:
        raise CredentialDeliveryError(f"private key file integrity check failed: {source}")
    return RecipientPrivateKey(
        key=private_key,
        public_key=public_key,
        fingerprint=fingerprint,
    )


def encrypt_credential_bundle(
    credential: Mapping[str, Any],
    *,
    recipient: RecipientPublicKey,
    credential_type: str,
    key_name: str,
    region: str,
) -> dict[str, Any]:
    """Encrypt a credential payload so only the recipient private key can open it."""
    created_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "format": PAYLOAD_FORMAT,
        "version": BUNDLE_VERSION,
        "credential_type": credential_type,
        "key_name": key_name,
        "region": region,
        "created_at": created_at,
        "recipient_key_fingerprint": recipient.fingerprint,
        "credential": dict(credential),
    }
    plaintext = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    ciphertext = SealedBox(recipient.key).encrypt(plaintext)
    return {
        "delivery_mode": "encrypted_bundle",
        "bundle_format": BUNDLE_FORMAT,
        "bundle_version": BUNDLE_VERSION,
        "algorithm": ALGORITHM,
        "encoding": "base64url",
        "recipient_key_fingerprint": recipient.fingerprint,
        "credential_type": credential_type,
        "key_name": key_name,
        "region": region,
        "created_at": created_at,
        "ciphertext": _b64url_encode(ciphertext),
    }


def _unwrap_bundle(document: Mapping[str, Any]) -> Mapping[str, Any]:
    if document.get("ok") is True and isinstance(document.get("data"), Mapping):
        return document["data"]
    return document


def decrypt_credential_bundle(
    document: Mapping[str, Any],
    *,
    recipient: RecipientPrivateKey,
) -> dict[str, Any]:
    """Decrypt and validate a credential bundle on the recipient device."""
    bundle = _unwrap_bundle(document)
    expected = {
        "delivery_mode": "encrypted_bundle",
        "bundle_format": BUNDLE_FORMAT,
        "bundle_version": BUNDLE_VERSION,
        "algorithm": ALGORITHM,
        "encoding": "base64url",
        "recipient_key_fingerprint": recipient.fingerprint,
    }
    for field_name, expected_value in expected.items():
        if bundle.get(field_name) != expected_value:
            raise CredentialDeliveryError(f"encrypted bundle has an invalid {field_name} value")
    ciphertext = _b64url_decode(str(bundle.get("ciphertext", "")), field_name="ciphertext")
    try:
        plaintext = SealedBox(recipient.key).decrypt(ciphertext)
    except CryptoError as exc:
        raise CredentialDeliveryError(
            "encrypted bundle could not be decrypted by this recipient key"
        ) from exc
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialDeliveryError("decrypted credential payload is invalid") from exc
    if not isinstance(payload, dict):
        raise CredentialDeliveryError("decrypted credential payload must be an object")
    if payload.get("format") != PAYLOAD_FORMAT or payload.get("version") != BUNDLE_VERSION:
        raise CredentialDeliveryError("decrypted credential payload has an unsupported format")
    if payload.get("recipient_key_fingerprint") != recipient.fingerprint:
        raise CredentialDeliveryError("decrypted credential payload recipient does not match")
    for field_name in ("credential_type", "key_name", "region", "created_at"):
        if payload.get(field_name) != bundle.get(field_name):
            raise CredentialDeliveryError(
                f"encrypted bundle metadata does not match payload field {field_name}"
            )
    if not isinstance(payload.get("credential"), dict):
        raise CredentialDeliveryError("decrypted credential payload is missing credentials")
    return payload


def write_private_json_file(
    path: str | os.PathLike[str],
    document: Mapping[str, Any],
) -> Path:
    """Write decrypted credentials to a new owner-only JSON file."""
    destination = Path(path).expanduser()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(destination, flags, 0o600)
    except FileExistsError as exc:
        raise CredentialDeliveryError(f"output file already exists: {destination}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    os.chmod(destination, 0o600)
    return destination
