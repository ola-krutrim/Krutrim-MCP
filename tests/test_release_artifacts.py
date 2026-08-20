"""Release artifact policy tests."""

from __future__ import annotations

import pytest

from scripts.verify_release_artifacts import _is_forbidden


@pytest.mark.parametrize(
    "name",
    [
        "krutrim_mcp_server-1.0.1/tests/test_server.py",
        "krutrim_mcp_server-1.0.1/.cursor/mcp.json",
        "krutrim_mcp_server-1.0.1/deploy/hosted.env",
        "krutrim_mcp_server-1.0.1/deploy/hosted.env.production",
        "krutrim_mcp_server-1.0.1/deploy/tls/private.key",
        "krutrim_mcp_server-1.0.1/mcp-storage-key.bundle.json",
        "krutrim_mcp_server-1.0.1/Public Cloud - Service Deployment Checklist.xlsx",
    ],
)
def test_release_artifact_policy_rejects_private_files(name: str) -> None:
    assert _is_forbidden(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "krutrim_mcp_server-1.0.1/krutrim_mcp_server/server.py",
        "krutrim_mcp_server-1.0.1/.cursor/mcp.example.json",
        "krutrim_mcp_server-1.0.1/deploy/hosted.env.example",
        "krutrim_mcp_server-1.0.1/docs/encrypted-credential-delivery.md",
        "krutrim_mcp_server-1.0.1/uv.lock",
    ],
)
def test_release_artifact_policy_allows_public_distribution_files(name: str) -> None:
    assert _is_forbidden(name) is False
