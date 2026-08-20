"""FastMCP stdio server and CLI for local Krutrim Cloud clients."""

from __future__ import annotations

import argparse
import json
import logging
import warnings
from collections.abc import Sequence
from dataclasses import replace
from typing import Any

from mcp.server.fastmcp import FastMCP

from krutrim_mcp_server._version import __version__
from krutrim_mcp_server.client import (
    AuthError,
    get_session,
    init_session,
)
from krutrim_mcp_server.config import Settings
from krutrim_mcp_server.logging_utils import configure_logging
from krutrim_mcp_server.profiles import UNAVAILABLE_TOOLS, GuardedFastMCP
from krutrim_mcp_server.tools import (
    compute,
    dns,
    iam,
    kpod,
    kubernetes,
    meta,
    networking,
    storage,
)

logger = logging.getLogger(__name__)


def create_server(settings: Settings | None = None) -> FastMCP:
    """Create and configure the Krutrim MCP server."""
    cfg = settings or Settings.from_env()
    cfg.validate()
    configure_logging(cfg.log_level)
    init_session(cfg)

    mcp = GuardedFastMCP(
        "krutrim-cloud",
        server_version=__version__,
        instructions=(
            "Krutrim Cloud MCP server for core infrastructure. "
            "Prefer read tools (list_*, describe_*) before mutations. "
            "For region-scoped tools, ask the user to select a region and pass it "
            "explicitly; do not silently infer KRUTRIM_DEFAULT_REGION. "
            "Before create_instance, ask the user to select a region, call "
            "list_subnets for the selected VPC, and use only a returned "
            "subnets[].subnet_id (never parent_network_id). "
            "list_compute_flavors for CPU or list_gpu_compute_flavors for GPU in "
            "that region, and require the user to choose one of the returned flavors; "
            "never guess, infer, or silently default the VM instance type. "
            "Before create_kpod, call list_kpod_flavors and list_kpod_templates. Explain "
            "that both are authenticated live catalogs, while KPod flavor availability "
            "is a non-regional snapshot and does not reserve capacity. Require the user "
            "to select an exact selectable KPod create_value and the exact "
            "pod_template_id returned by list_kpod_templates, explicit HTTP and TCP "
            "port lists, explicit Jupyter and SSH choices, and approval of public port "
            "exposure; never guess a template or substitute compute or KKS flavor "
            "catalogs. "
            "A plain VPC request never includes a security group or rule; do not ask "
            "for or invoke security-group tools unless the user explicitly requests one. "
            "Mutating tools require confirm=true after the user verifies the operation. "
            "When KRUTRIM_MCP_READ_ONLY=true, mutations are blocked."
        ),
    )

    meta.register(mcp)
    networking.register(mcp)
    compute.register(mcp)
    storage.register(mcp)
    iam.register(mcp)
    dns.register(mcp)
    kubernetes.register(mcp)
    kpod.register(mcp)

    logger.info(
        "Krutrim MCP server ready (tools=%s, read_only=%s, default_region=%s)",
        len(mcp._tool_manager.list_tools()),
        cfg.read_only,
        cfg.default_region,
    )
    return mcp


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Krutrim Cloud MCP server")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--profile", help=argparse.SUPPRESS)
    parser.add_argument(
        "--read-only",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Block all mutating tools at execution time",
    )
    parser.add_argument("--doctor", action="store_true", help="Validate configuration and exit")
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print enabled tool names and exit",
    )
    return parser


def _apply_cli(settings: Settings, args: argparse.Namespace) -> Settings:
    overrides: dict[str, Any] = {}
    if args.profile is not None:
        warnings.warn(
            "--profile is deprecated and ignored; all supported non-secret tools "
            "are registered. Use --read-only to block mutations.",
            RuntimeWarning,
            stacklevel=2,
        )
    if args.read_only is not None:
        overrides["read_only"] = args.read_only
    updated = replace(settings, **overrides)
    updated.validate()
    return updated


def main(argv: Sequence[str] | None = None) -> None:
    """Run the local stdio MCP server or a diagnostic CLI action."""
    args = _parser().parse_args(argv)
    try:
        cfg = _apply_cli(Settings.from_env(), args)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    server = create_server(cfg)

    if args.doctor:
        session_health = get_session().health()
        credential_ready = bool(session_health["ok"])
        print(
            json.dumps(
                {
                    "ok": credential_ready,
                    "version": __version__,
                    "transport": "stdio",
                    "catalog": "all-supported",
                    "read_only": cfg.read_only,
                    "credentials_configured": cfg.credential_kind != "missing",
                    "configuration_ready": credential_ready,
                    "credential_kind": cfg.credential_kind,
                    "refresh_token_configured": bool(cfg.refresh_token),
                    "access_token_refresh_required": session_health[
                        "access_token_refresh_required"
                    ],
                    "authentication_verified": False,
                    "credential_ready": credential_ready,
                    "compatibility_disabled_tools": sorted(UNAVAILABLE_TOOLS),
                    "tool_count": len(server._tool_manager.list_tools()),
                },
                indent=2,
            )
        )
        if not credential_ready:
            raise SystemExit(1)
        return
    if args.list_tools:
        for tool in sorted(server._tool_manager.list_tools(), key=lambda item: item.name):
            print(tool.name)
        return

    try:
        get_session().ensure_ready()
    except AuthError as exc:
        raise SystemExit(str(exc)) from exc

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
