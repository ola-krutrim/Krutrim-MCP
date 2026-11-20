"""Direct adapter for the load balancer target-group ASG attachment routes.

krutrim-client 0.8.9 has no methods for attaching an ASG to a target group or
detaching it, so these call ``/api/v3/loadBalancer/targetgroup/{krn}/asg-attachment``
and ``/asg-detachment`` directly. Replace them with SDK methods once they exist.
"""

import unicodedata
from typing import Any

import httpx
from krutrim_client import KrutrimClient

from krutrim_mcp_server.adapters._http import response_payload

_TG = "/api/v3/loadBalancer/targetgroup"


def _segment(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    value = value.strip()
    if (
        value in {".", ".."}
        or any(char in value for char in " /?#\\%")
        or any(unicodedata.category(char) == "Cc" for char in value)
    ):
        raise ValueError(f"{label}: Request blocked: identifiers must be plain IDs or KRNs")
    return value


def _post(
    client: KrutrimClient,
    path: str,
    *,
    region: str,
    customer_id: str,
    account_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    response = client.post(
        path,
        cast_to=httpx.Response,
        body=body,
        options={
            "headers": {
                "x-region": region,
                "k-customer-id": customer_id,
                "x-account-id": account_id,
            },
            "max_retries": 0,
        },
    )
    return response_payload(response)


def attach_asg_to_target_group(
    client: KrutrimClient,
    *,
    target_group_krn: str,
    body: dict[str, Any],
    region: str,
    customer_id: str,
    account_id: str,
) -> dict[str, Any]:
    return _post(
        client,
        f"{_TG}/{_segment(target_group_krn, 'target_group_krn')}/asg-attachment",
        region=region,
        customer_id=customer_id,
        account_id=account_id,
        body=body,
    )


def detach_asg_from_target_group(
    client: KrutrimClient,
    *,
    target_group_krn: str,
    body: dict[str, Any],
    region: str,
    customer_id: str,
    account_id: str,
) -> dict[str, Any]:
    return _post(
        client,
        f"{_TG}/{_segment(target_group_krn, 'target_group_krn')}/asg-detachment",
        region=region,
        customer_id=customer_id,
        account_id=account_id,
        body=body,
    )
