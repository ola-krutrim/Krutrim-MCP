"""Tests for recipient-encrypted credential delivery."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.credential_cli import main as credential_cli_main
from krutrim_mcp_server.credential_delivery import (
    CredentialDeliveryError,
    decrypt_credential_bundle,
    encrypt_credential_bundle,
    generate_recipient_key_file,
    load_recipient_private_key,
    parse_recipient_public_key,
)
from krutrim_mcp_server.server import create_server
from tests.auth_tokens import TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN


def _settings(**overrides: object) -> Settings:
    values = dict(
        api_key=None,
        base_url="https://cloud.olakrutrim.com",
        default_region="",
        read_only=False,
        log_level="ERROR",
        client_max_retries=0,
        tool_profile="admin",
        enable_sensitive_tools=True,
        access_token=TEST_ACCESS_TOKEN,
        refresh_token=TEST_REFRESH_TOKEN,
    )
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _recipient(tmp_path: Path):
    key_path = tmp_path / "recipient.key"
    generated = generate_recipient_key_file(key_path)
    private = load_recipient_private_key(key_path)
    public = parse_recipient_public_key(
        generated["public_key"],
        expected_fingerprint=generated["fingerprint"],
    )
    return key_path, generated, public, private


def test_encrypted_bundle_round_trip_contains_no_plaintext(tmp_path: Path) -> None:
    _, _, public, private = _recipient(tmp_path)
    bundle = encrypt_credential_bundle(
        {"access_key": "AKIA-EXAMPLE", "secret_key": "one-time-secret"},
        recipient=public,
        credential_type="krutrim_object_storage_access_key",
        key_name="demo-key",
        region="In-Bangalore-1",
    )

    encoded = json.dumps(bundle)
    assert "AKIA-EXAMPLE" not in encoded
    assert "one-time-secret" not in encoded

    payload = decrypt_credential_bundle(bundle, recipient=private)
    assert payload["credential"] == {
        "access_key": "AKIA-EXAMPLE",
        "secret_key": "one-time-secret",
    }


def test_encrypted_bundle_rejects_wrong_recipient(tmp_path: Path) -> None:
    _, _, public, _ = _recipient(tmp_path / "first")
    _, _, _, wrong_private = _recipient(tmp_path / "second")
    bundle = encrypt_credential_bundle(
        {"access_key": "access", "secret_key": "secret"},
        recipient=public,
        credential_type="krutrim_object_storage_access_key",
        key_name="demo-key",
        region="In-Bangalore-1",
    )

    with pytest.raises(CredentialDeliveryError, match="recipient_key_fingerprint"):
        decrypt_credential_bundle(bundle, recipient=wrong_private)


def test_private_key_file_requires_owner_only_permissions(tmp_path: Path) -> None:
    key_path, _, _, _ = _recipient(tmp_path)
    os.chmod(key_path, 0o640)

    with pytest.raises(CredentialDeliveryError, match="group or others"):
        load_recipient_private_key(key_path)


def test_private_key_path_must_be_a_regular_file(tmp_path: Path) -> None:
    key_directory = tmp_path / "recipient.key"
    key_directory.mkdir()

    with pytest.raises(CredentialDeliveryError, match="regular file"):
        load_recipient_private_key(key_directory)


def test_credential_cli_generates_and_decrypts_owner_only_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key_path = tmp_path / "recipient.key"
    credential_cli_main(["init", "--private-key", str(key_path)])
    generated = json.loads(capsys.readouterr().out)
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    private = load_recipient_private_key(key_path)
    public = parse_recipient_public_key(
        generated["public_key"],
        expected_fingerprint=generated["fingerprint"],
    )
    bundle = encrypt_credential_bundle(
        {"access_key": "access", "secret_key": "secret"},
        recipient=public,
        credential_type="krutrim_object_storage_access_key",
        key_name="cli-key",
        region="In-Hyderabad-1",
    )
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps({"ok": True, "data": bundle}), encoding="utf-8")
    output_path = tmp_path / "credentials.json"

    credential_cli_main(
        [
            "decrypt",
            "--private-key",
            str(key_path),
            "--bundle",
            str(bundle_path),
            "--output",
            str(output_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600
    decrypted = json.loads(output_path.read_text(encoding="utf-8"))
    assert decrypted == decrypt_credential_bundle(bundle, recipient=private)


@pytest.mark.parametrize(
    ("region", "tier"),
    [
        ("In-Bangalore-1", "tier-1"),
        ("In-Hyderabad-1", "tier-2"),
    ],
)
def test_create_storage_access_key_returns_only_encrypted_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    region: str,
    tier: str,
) -> None:
    _, generated, _, private = _recipient(tmp_path)
    mock_client = MagicMock()
    mock_client.kos.accessKeys.create_access_keys.return_value = {
        "access_key": "AKIA-CREATED",
        "secret_key": "created-one-time-secret",
        "message": "created",
    }
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_module

    monkeypatch.setattr(client_module.get_session(), "get_client", lambda: mock_client)
    tool = server._tool_manager.get_tool("create_storage_access_key")
    assert tool is not None
    properties = tool.parameters["properties"]
    delivery_mode = properties["delivery_mode"]
    assert delivery_mode.get("const", delivery_mode.get("enum")) in (
        "encrypted_bundle",
        ["encrypted_bundle"],
    )
    assert properties["delivery_mode"]["default"] == "encrypted_bundle"
    assert {"recipient_public_key", "recipient_key_fingerprint"}.issubset(
        tool.parameters["required"]
    )

    result = tool.fn(
        key_name="demo-key",
        recipient_public_key=generated["public_key"],
        recipient_key_fingerprint=generated["fingerprint"],
        delivery_mode="encrypted_bundle",
        region=region,
        confirm=True,
    )

    serialized = json.dumps(result.model_dump(mode="json"))
    assert "AKIA-CREATED" not in serialized
    assert "created-one-time-secret" not in serialized
    payload = decrypt_credential_bundle(result.data, recipient=private)
    assert payload["credential"]["access_key"] == "AKIA-CREATED"
    assert payload["credential"]["secret_key"] == "created-one-time-secret"
    mock_client.kos.accessKeys.create_access_keys.assert_called_once_with(
        key_name="demo-key",
        region=region,
        x_region_id=region,
        extra_headers={"x-tier": tier},
    )
    mock_client.kos.accessKeys.delete_access_keys.assert_not_called()


def test_create_storage_access_key_rejects_bad_fingerprint_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, generated, _, _ = _recipient(tmp_path)
    mock_client = MagicMock()
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_module

    monkeypatch.setattr(client_module.get_session(), "get_client", lambda: mock_client)

    with pytest.raises(ToolError, match="does not match"):
        server._tool_manager.get_tool("create_storage_access_key").fn(
            key_name="demo-key",
            recipient_public_key=generated["public_key"],
            recipient_key_fingerprint=f"sha256:{'0' * 64}",
            delivery_mode="encrypted_bundle",
            region="In-Bangalore-1",
            confirm=True,
        )

    mock_client.kos.accessKeys.create_access_keys.assert_not_called()


def test_create_storage_access_key_rolls_back_when_encryption_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, generated, _, _ = _recipient(tmp_path)
    mock_client = MagicMock()
    mock_client.kos.accessKeys.create_access_keys.return_value = {
        "access_key": "AKIA-CREATED",
        "secret_key": "created-one-time-secret",
    }
    mock_client.kos.accessKeys.list.return_value = [
        {
            "access_key": "AKIA-CREATED",
            "region": "In-Hyderabad-1",
            "tier": "tier-2",
        }
    ]
    server = create_server(_settings())
    from krutrim_mcp_server import client as client_module
    from krutrim_mcp_server.tools.storage import access_keys as access_keys_module

    monkeypatch.setattr(client_module.get_session(), "get_client", lambda: mock_client)
    monkeypatch.setattr(
        access_keys_module,
        "encrypt_credential_bundle",
        MagicMock(side_effect=RuntimeError("encryption unavailable")),
    )

    with pytest.raises(ToolError, match="was rolled back"):
        server._tool_manager.get_tool("create_storage_access_key").fn(
            key_name="demo-key",
            recipient_public_key=generated["public_key"],
            recipient_key_fingerprint=generated["fingerprint"],
            delivery_mode="encrypted_bundle",
            region="In-Hyderabad-1",
            confirm=True,
        )

    mock_client.kos.accessKeys.delete_access_keys.assert_called_once_with(
        access_key_id="AKIA-CREATED",
        x_region_id="In-Hyderabad-1",
        extra_headers={"x-tier": "tier-2"},
    )
