"""The supported SDK floor includes the Sandbox API."""

from importlib.metadata import version


def test_sandbox_release_version_matches_installed_metadata() -> None:
    from krutrim_mcp_server._version import __version__

    assert __version__ == "1.0.5"
    assert version("krutrim-mcp-server") == __version__


def test_sdk_includes_sandbox_release() -> None:
    installed = tuple(int(part) for part in version("krutrim-client").split("."))
    assert installed >= (0, 6, 1)
