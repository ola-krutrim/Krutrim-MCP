"""Local key and decrypt commands for recipient-encrypted MCP credentials."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from krutrim_mcp_server.credential_delivery import (
    CredentialDeliveryError,
    decrypt_credential_bundle,
    generate_recipient_key_file,
    load_recipient_private_key,
    write_private_json_file,
)

DEFAULT_PRIVATE_KEY_FILE = "~/.config/krutrim-mcp/credential-recipient.key"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate recipient keys and decrypt Krutrim MCP credential bundles"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="Generate a local recipient key pair",
    )
    init_parser.add_argument(
        "--private-key",
        default=DEFAULT_PRIVATE_KEY_FILE,
        help=f"Owner-only private key file (default: {DEFAULT_PRIVATE_KEY_FILE})",
    )

    show_parser = subparsers.add_parser(
        "show-public-key",
        help="Print the public key and fingerprint for an existing private key",
    )
    show_parser.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY_FILE)

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt an MCP credential bundle into a new owner-only JSON file",
    )
    decrypt_parser.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY_FILE)
    decrypt_parser.add_argument(
        "--bundle",
        required=True,
        help="Bundle JSON file, or - to read JSON from standard input",
    )
    decrypt_parser.add_argument(
        "--output",
        required=True,
        help="New file to receive decrypted credentials (must not already exist)",
    )
    return parser


def _read_bundle(path: str) -> dict[str, Any]:
    try:
        raw = sys.stdin.read() if path == "-" else Path(path).expanduser().read_text("utf-8")
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise CredentialDeliveryError("bundle input is not valid readable JSON") from exc
    if not isinstance(document, dict):
        raise CredentialDeliveryError("bundle input must contain a JSON object")
    return document


def main(argv: Sequence[str] | None = None) -> None:
    """Run the credential helper CLI."""
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = generate_recipient_key_file(args.private_key)
        elif args.command == "show-public-key":
            recipient = load_recipient_private_key(args.private_key)
            result = {
                "private_key_file": str(Path(args.private_key).expanduser()),
                "public_key": recipient.public_key,
                "fingerprint": recipient.fingerprint,
            }
        else:
            recipient = load_recipient_private_key(args.private_key)
            payload = decrypt_credential_bundle(
                _read_bundle(args.bundle),
                recipient=recipient,
            )
            output = write_private_json_file(args.output, payload)
            result = {
                "ok": True,
                "output_file": str(output),
                "credential_type": payload["credential_type"],
                "key_name": payload["key_name"],
                "region": payload["region"],
            }
    except CredentialDeliveryError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
