"""Shared Krutrim Object Storage region and tier routing."""

from typing import Any

KOS_TIER_BY_REGION = {
    "In-Bangalore-1": "tier-1",
    "In-Hyderabad-1": "tier-2",
}
KOS_TIERS = frozenset(KOS_TIER_BY_REGION.values())


def storage_tier_for_region(region: str) -> str:
    try:
        return KOS_TIER_BY_REGION[region]
    except KeyError as exc:
        raise ValueError(
            f"object-storage operations are not configured for region {region!r}"
        ) from exc


def response_value(response: Any, field_name: str) -> Any:
    if isinstance(response, dict):
        return response.get(field_name)
    return getattr(response, field_name, None)
