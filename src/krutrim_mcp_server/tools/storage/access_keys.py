"""Object storage MCP tools."""

from typing import Any, Literal

from pydantic import Field

from krutrim_mcp_server.client import get_session
from krutrim_mcp_server.credential_delivery import (
    RecipientPublicKey,
    encrypt_credential_bundle,
    parse_recipient_public_key,
)
from krutrim_mcp_server.guards import ensure_confirmed, ensure_writable
from krutrim_mcp_server.tools import (
    CONFIRM_FIELD,
    REGION_FIELD,
    Region,
    resolve_region,
    run_tool,
    settings,
)
from krutrim_mcp_server.tools.storage.kos_routing import (
    KOS_TIERS,
    response_value,
    storage_tier_for_region,
)

CredentialDeliveryMode = Literal["encrypted_bundle"]
DELIVERY_MODE_FIELD = Field(
    "encrypted_bundle",
    description="Deliver generated credentials only as a recipient-encrypted bundle.",
)
RECIPIENT_PUBLIC_KEY_FIELD = Field(
    ...,
    min_length=1,
    description=(
        "Public key produced by krutrim-mcp-credentials. This is public material, "
        "not the private decryption key."
    ),
)
RECIPIENT_FINGERPRINT_FIELD = Field(
    ...,
    pattern=r"^sha256:[0-9a-fA-F]{64}$",
    description=(
        "Fingerprint shown by krutrim-mcp-credentials; verify it with the user before "
        "creating the access key."
    ),
)


def _preflight_access_key_tier(
    client: Any,
    *,
    access_key_id: str,
    region: str,
) -> str:
    inventory = client.kos.accessKeys.list()
    if not isinstance(inventory, (list, tuple)):
        raise ValueError(
            "storage access-key inventory returned an invalid response; operation blocked"
        )

    matches = [
        item
        for item in inventory
        if access_key_id
        in {
            response_value(item, "access_key"),
            response_value(item, "access_key_id"),
        }
    ]
    if len(matches) != 1:
        raise ValueError(
            "storage access-key preflight did not return exactly the requested key; "
            "operation blocked"
        )

    key = matches[0]
    key_region = response_value(key, "region")
    if key_region != region:
        raise ValueError(
            f"storage access key belongs to region {key_region!r}, not selected region {region!r}; "
            "operation blocked"
        )

    tier = response_value(key, "tier")
    if tier not in KOS_TIERS:
        raise ValueError(
            "storage access-key preflight did not return a supported tier; operation blocked"
        )
    return tier


def _created_credential(response: Any) -> tuple[dict[str, str], str | None]:
    access_key = response_value(response, "access_key")
    secret_key = response_value(response, "secret_key")
    if not isinstance(access_key, str) or not access_key.strip():
        raise RuntimeError("Krutrim did not return an access key ID after creation")
    if not isinstance(secret_key, str) or not secret_key.strip():
        raise RuntimeError("Krutrim did not return the one-time secret after creation")
    credential = {
        "access_key": access_key,
        "secret_key": secret_key,
    }
    message = response_value(response, "message")
    if isinstance(message, str) and message.strip():
        credential["message"] = message
    return credential, access_key


def _rollback_created_key(client: Any, access_key_id: str, region: str) -> None:
    tier = _preflight_access_key_tier(
        client,
        access_key_id=access_key_id,
        region=region,
    )
    client.kos.accessKeys.delete_access_keys(
        access_key_id=access_key_id,
        x_region_id=region,
        extra_headers={"x-tier": tier},
    )


def _deliver_created_credential(
    *,
    client: Any,
    response: Any,
    recipient: RecipientPublicKey,
    key_name: str,
    region: str,
) -> dict[str, Any]:
    access_key_id = response_value(response, "access_key")
    try:
        credential, access_key_id = _created_credential(response)
        return encrypt_credential_bundle(
            credential,
            recipient=recipient,
            credential_type="krutrim_object_storage_access_key",
            key_name=key_name,
            region=region,
        )
    except Exception as delivery_exc:
        if not isinstance(access_key_id, str) or not access_key_id.strip():
            raise RuntimeError(
                "Credential delivery failed and the create response did not contain an access "
                f"key ID. Reconcile and delete the key named {key_name!r} in {region!r} before "
                "retrying."
            ) from delivery_exc
        try:
            _rollback_created_key(client, access_key_id, region)
        except Exception as rollback_exc:
            raise RuntimeError(
                "Credential delivery failed and automatic rollback also failed. Delete the "
                f"newly created key named {key_name!r} in {region!r} before retrying."
            ) from rollback_exc
        raise RuntimeError(
            "Credential delivery failed; the newly created storage access key was rolled back."
        ) from delivery_exc


def register(mcp: Any) -> None:
    @mcp.tool()
    def create_storage_access_key(
        key_name: str,
        recipient_public_key: str = RECIPIENT_PUBLIC_KEY_FIELD,
        recipient_key_fingerprint: str = RECIPIENT_FINGERPRINT_FIELD,
        delivery_mode: CredentialDeliveryMode = DELIVERY_MODE_FIELD,
        region: Region = REGION_FIELD,
        confirm: bool = CONFIRM_FIELD,
    ) -> str:
        """Create an object-storage access key and return only a recipient-encrypted bundle."""

        def _run() -> Any:
            ensure_writable(settings(), "create_storage_access_key")
            if delivery_mode != "encrypted_bundle":
                raise ValueError("delivery_mode must be 'encrypted_bundle'")
            recipient = parse_recipient_public_key(
                recipient_public_key,
                expected_fingerprint=recipient_key_fingerprint,
            )
            ensure_confirmed(
                confirm,
                "create_storage_access_key",
                f"{key_name} for recipient {recipient.fingerprint}",
            )
            x_region = resolve_region(region)
            client = get_session().get_client()
            response = client.kos.accessKeys.create_access_keys(
                key_name=key_name,
                region=x_region,
                x_region_id=x_region,
                extra_headers={"x-tier": storage_tier_for_region(x_region)},
            )
            return _deliver_created_credential(
                client=client,
                response=response,
                recipient=recipient,
                key_name=key_name,
                region=x_region,
            )

        return run_tool(_run)

    @mcp.tool()
    def delete_storage_access_key(
        access_key_id: str,
        confirm: bool = CONFIRM_FIELD,
        region: Region = REGION_FIELD,
    ) -> str:
        """Delete an object-storage access key."""

        def _run() -> Any:
            ensure_writable(settings(), "delete_storage_access_key")
            ensure_confirmed(confirm, "delete_storage_access_key", access_key_id)
            x_region = resolve_region(region)
            client = get_session().get_client()
            tier = _preflight_access_key_tier(
                client,
                access_key_id=access_key_id,
                region=x_region,
            )
            return client.kos.accessKeys.delete_access_keys(
                access_key_id=access_key_id,
                x_region_id=x_region,
                extra_headers={"x-tier": tier},
            )

        return run_tool(_run)
