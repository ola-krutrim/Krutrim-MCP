"""Certificate manager (KCM) MCP tools."""

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.compat import sdk_raw_result, sdk_response_json
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import CONFIRM_FIELD, run_tool, settings
from krutrim_mcp_server.tools.shared.common import drop_none

_MAX_CERT_BYTES = 1024 * 1024
_CERT_SUFFIXES = {".pem", ".crt", ".cer", ".cert", ".pfx", ".p12"}


def _require_text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _read_cert_file(path: str) -> tuple[str, bytes]:
    """Read a local certificate file for upload, failing closed on anything odd.

    The MCP server runs on the user's machine, so a path argument is an
    arbitrary-file-read primitive if a prompt is manipulated. Restrict uploads to
    small regular files with a certificate extension.
    """
    raw = _require_text(path, "cert_file_path")
    file_path = Path(raw).expanduser()
    try:
        resolved = file_path.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise ValueError(f"certificate file not found: {raw}") from None
    if not resolved.is_file():
        raise ValueError(f"cert_file_path must be a regular file: {raw}")
    if resolved.suffix.lower() not in _CERT_SUFFIXES:
        raise ValueError(
            "certificate file has an unsupported extension "
            f"{resolved.suffix!r}; expected one of {', '.join(sorted(_CERT_SUFFIXES))}"
        )
    size = resolved.stat().st_size
    if size == 0:
        raise ValueError("certificate file is empty")
    if size > _MAX_CERT_BYTES:
        raise ValueError(
            f"certificate file is too large ({size} bytes; limit {_MAX_CERT_BYTES})"
        )
    return resolved.name, resolved.read_bytes()


def register(mcp: Any) -> None:
    @mcp.tool()
    def list_certificates(vpc_id: str) -> str:
        """List certificates stored in the Krutrim certificate manager for a VPC.

        vpc_id is the full, unmasked VPC KRN.
        """

        def _run() -> Any:
            vpc = _require_text(vpc_id, "vpc_id")
            client = get_session().get_client()
            return sdk_response_json(client.certs.with_raw_response.list, vpc_id=vpc)

        return run_tool(_run)

    @mcp.tool()
    def describe_certificate(cert_id: str) -> str:
        """Describe one certificate by id (subject, validity, tags)."""

        def _run() -> Any:
            cert = _require_text(cert_id, "cert_id")
            client = get_session().get_client()
            return sdk_response_json(client.certs.with_raw_response.retrieve, cert_id=cert)

        return run_tool(_run)

    @mcp.tool()
    def get_expiring_certificates(vpc_id: str, date: str) -> str:
        """List certificates in a VPC that expire on or before a date.

        date must be YYYY-MM-DD.
        """

        def _run() -> Any:
            vpc = _require_text(vpc_id, "vpc_id")
            value = _require_text(date, "date")
            try:
                datetime.strptime(value, "%Y-%m-%d")
            except ValueError:
                raise ValueError("date must be in YYYY-MM-DD format") from None
            client = get_session().get_client()
            return sdk_response_json(
                client.certs.with_raw_response.get_expiring,
                date=value,
                vpc_id=vpc,
            )

        return run_tool(_run)

    @mcp.tool()
    def import_certificate(
        vpc_id: str,
        cert_file_path: str,
        name: Optional[str] = None,
        tags: Optional[str] = None,
        flag: Optional[str] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Import a certificate file into the certificate manager.

        cert_file_path is a local file on the machine running this MCP server:
        a regular file of at most 1 MiB with a .pem, .crt, .cer, .cert, .pfx or
        .p12 extension. Its contents are uploaded to Krutrim Cloud. tags is
        passed through as the API's string form. vpc_id is the full VPC KRN.
        """

        def _run() -> Any:
            ensure_writable(settings(), "import_certificate")
            ensure_confirmed(confirm, "import_certificate", name or cert_file_path)
            vpc = _require_text(vpc_id, "vpc_id")
            filename, content = _read_cert_file(cert_file_path)
            client = get_session().get_client()
            return sdk_raw_result(
                client.certs.with_raw_response.import_file,
                **drop_none(
                    {
                        "vpc_id": vpc,
                        "cert_file": (filename, content),
                        "name": name,
                        "tags": tags,
                        "flag": flag,
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def update_certificate(
        cert_id: str,
        vpc_id: str,
        cert_file_path: Optional[str] = None,
        flag: Optional[str] = None,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Replace a certificate's file and/or flag.

        Provide cert_file_path (same restrictions as import_certificate) and/or
        flag; at least one is required. This overwrites the stored certificate,
        which load balancers using it will pick up.
        """

        def _run() -> Any:
            ensure_writable(settings(), "update_certificate")
            ensure_confirmed(confirm, "update_certificate", cert_id)
            cert = _require_text(cert_id, "cert_id")
            vpc = _require_text(vpc_id, "vpc_id")
            if cert_file_path is None and flag is None:
                raise ValueError("provide at least one of cert_file_path or flag")
            upload = _read_cert_file(cert_file_path) if cert_file_path is not None else None
            client = get_session().get_client()
            return sdk_raw_result(
                client.certs.tags.with_raw_response.updateCertificate,
                **drop_none(
                    {
                        "path_cert_id": cert,
                        "vpc_id": vpc,
                        "cert_file": upload,
                        "flag": flag,
                    }
                ),
            )

        return run_tool(_run)

    @mcp.tool()
    def get_certificate_tag_value(cert_id: str, tag_name: str) -> str:
        """Get the value of one tag on a certificate."""

        def _run() -> Any:
            cert = _require_text(cert_id, "cert_id")
            tag = _require_text(tag_name, "tag_name")
            client = get_session().get_client()
            return sdk_response_json(
                client.certs.tags.with_raw_response.getTagValue,
                cert_id=cert,
                tag_name=tag,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_certificate(cert_id: str, confirm: bool = CONFIRM_FIELD) -> str:
        """Delete a certificate by id. Detach it from load balancers first."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_certificate")
            ensure_confirmed(confirm, "delete_certificate", cert_id)
            cert = _require_text(cert_id, "cert_id")
            client = get_session().get_client()
            return sdk_raw_result(client.certs.with_raw_response.delete, cert)

        return run_tool(_run)

    @mcp.tool()
    def add_certificate_tags(
        cert_id: str,
        tags: dict[str, str],
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Add key/value tags to a certificate."""

        def _run() -> Any:
            ensure_writable(settings(), "add_certificate_tags")
            ensure_confirmed(confirm, "add_certificate_tags", cert_id)
            cert = _require_text(cert_id, "cert_id")
            valid_tags = isinstance(tags, dict) and all(
                isinstance(key, str) and isinstance(value, str) for key, value in tags.items()
            )
            if not tags or not valid_tags:
                raise ValueError("tags must be a non-empty object of string keys and values")
            client = get_session().get_client()
            return sdk_raw_result(
                client.certs.tags.with_raw_response.addCertificateTag,
                path_cert_id=cert,
                tags=tags,
            )

        return run_tool(_run)
