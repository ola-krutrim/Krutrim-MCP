#!/usr/bin/env python3
"""Release helpers: version consistency checks and changelog notes."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_RUNTIME_VERSION = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)
_PACKAGE_VERSION = re.compile(r'^version = "([^"]+)"$', re.MULTILINE)


def package_version(root: Path = ROOT) -> str:
    match = _PACKAGE_VERSION.search((root / "pyproject.toml").read_text())
    if match is None:
        raise SystemExit("could not read the package version from pyproject.toml")
    return match.group(1)


def runtime_version(root: Path = ROOT) -> str:
    source = (root / "src/krutrim_mcp_server/_version.py").read_text()
    match = _RUNTIME_VERSION.search(source)
    if match is None:
        raise SystemExit("could not read the runtime version")
    return match.group(1)


def changelog_notes(version: str, root: Path = ROOT) -> str:
    lines = (root / "CHANGELOG.md").read_text().splitlines()
    heading = re.compile(rf"^## {re.escape(version)}(?:\s|$)")
    start = next((i for i, line in enumerate(lines) if heading.match(line)), None)
    if start is None:
        raise SystemExit(f"CHANGELOG.md has no section for {version}")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    notes = "\n".join(lines[start + 1 : end]).strip()
    if not notes:
        raise SystemExit(f"CHANGELOG.md section for {version} is empty")
    return notes


def check(tag: str | None, root: Path = ROOT) -> str:
    """Return the release version, or exit if the sources disagree."""
    version = package_version(root)
    runtime = runtime_version(root)
    if runtime != version:
        raise SystemExit(f"runtime version {runtime} != package version {version}")
    if tag is not None and tag != f"v{version}":
        raise SystemExit(f"tag {tag} != expected tag v{version}")
    changelog_notes(version, root)
    return version


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check_parser = commands.add_parser("check", help="verify versions and print the version")
    check_parser.add_argument("--tag", help="release tag that must equal v<version>")
    notes_parser = commands.add_parser("notes", help="print the changelog section")
    notes_parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if args.command == "check":
        print(check(args.tag))
    else:
        print(changelog_notes(args.version))


if __name__ == "__main__":
    main()
