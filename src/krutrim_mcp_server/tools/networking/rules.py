"""Shared security-group rule types and validation."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

Port = Annotated[
    int,
    Field(
        ge=0,
        le=65535,
        description=(
            "User-supplied inclusive port or range boundary. Required unless protocol "
            "is 'all'; the MCP maps 'all' to the API range 1 through 65535."
        ),
    ),
]
ALL_PROTOCOL_PORT_MIN = 1
ALL_PROTOCOL_PORT_MAX = 65535
Direction = Annotated[
    Literal["ingress", "egress"],
    Field(description="Whether the rule controls inbound or outbound traffic"),
]
EtherType = Annotated[
    Literal["ipv4", "ipv6"],
    Field(description="IP address family for the rule and its remote prefix"),
]
Protocol = Annotated[
    Literal["tcp", "udp", "icmp", "all"],
    Field(
        description=(
            "Network protocol explicitly requested by the user. 'all' permits every "
            "protocol and is passed unchanged to the Krutrim API."
        )
    ),
]
PublicIngressAcknowledgement = Annotated[
    bool,
    Field(
        description=(
            "Set true only after the user explicitly approves exposing this ingress rule "
            "to every address. This is separate from the general mutation confirmation."
        )
    ),
]
RuleRequestAcknowledgement = Annotated[
    bool,
    Field(
        description=(
            "Set true only when the user explicitly requested a security-group rule and "
            "supplied its direction, ethertype, protocol, and remote prefix. The user must "
            "also supply ports unless protocol is 'all', which maps to 1-65535. Never infer "
            "a rule from a security-group-only request."
        )
    ),
]


def normalize_security_group_rule_ports(
    *,
    protocol: str,
    port_min: int | None,
    port_max: int | None,
) -> tuple[int, int]:
    """Return the API port range, deriving only the fixed all-protocol range."""
    if protocol == "all":
        return ALL_PROTOCOL_PORT_MIN, ALL_PROTOCOL_PORT_MAX
    if port_min is None or port_max is None:
        raise ValueError("port_min and port_max are required unless protocol=all")
    if port_min > port_max:
        raise ValueError("port_min must be less than or equal to port_max")
    return port_min, port_max


class SecurityGroupRuleSpec(BaseModel):
    """A complete rule supplied explicitly by the user for combined SG creation."""

    model_config = ConfigDict(extra="forbid")

    direction: Direction
    ethertype: EtherType
    protocol: Protocol
    port_min: Optional[Port] = None
    port_max: Optional[Port] = None
    remote_ip_prefix: str = Field(
        min_length=1,
        description="User-specified source or destination CIDR for this rule",
    )

    @model_validator(mode="after")
    def normalize_port_range(self) -> "SecurityGroupRuleSpec":
        self.port_min, self.port_max = normalize_security_group_rule_ports(
            protocol=self.protocol,
            port_min=self.port_min,
            port_max=self.port_max,
        )
        return self


def validate_security_group_rule(
    *,
    direction: Direction,
    ethertype: EtherType,
    protocol: Protocol,
    port_min: int | None,
    port_max: int | None,
    remote_ip_prefix: str,
    allow_public_ingress: bool,
) -> tuple[int, int]:
    """Validate a rule and return the port range required by the API."""
    if protocol not in {"tcp", "udp", "icmp", "all"}:
        raise ValueError("protocol must be one of: tcp, udp, icmp, all")
    normalized_ports = normalize_security_group_rule_ports(
        protocol=protocol,
        port_min=port_min,
        port_max=port_max,
    )
    network = ipaddress.ip_network(remote_ip_prefix, strict=False)
    expected_version = 4 if ethertype == "ipv4" else 6
    if network.version != expected_version:
        raise ValueError(f"remote_ip_prefix must match ethertype={ethertype}")
    if direction == "ingress" and network.prefixlen == 0 and not allow_public_ingress:
        raise ValueError(
            "World-open ingress requires allow_public_ingress=true after explicit user approval"
        )
    return normalized_ports
