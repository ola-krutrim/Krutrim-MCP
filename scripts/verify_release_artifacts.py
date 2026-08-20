#!/usr/bin/env python3
"""Validate local release contents or compare them with a PyPI index."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


def _release_files(dist: Path) -> list[Path]:
    files = sorted(
        path
        for path in dist.iterdir()
        if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    )
    if len(files) != 2:
        raise SystemExit(f"expected one wheel and one sdist in {dist}, found: {files}")
    if sum(path.suffix == ".whl" for path in files) != 1:
        raise SystemExit("release must contain exactly one wheel")
    if sum(path.name.endswith(".tar.gz") for path in files) != 1:
        raise SystemExit("release must contain exactly one source distribution")
    return files


def _archive_names(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    with tarfile.open(path) as archive:
        return archive.getnames()


def _is_forbidden(name: str) -> bool:
    path = PurePosixPath(name)
    lowered = name.lower()
    parts = {part.lower() for part in path.parts}
    basename = path.name.lower()
    if "tests" in parts:
        return True
    private_env = (
        basename == ".env"
        or basename.endswith(".env")
        or (".env." in basename and not basename.endswith(".env.example"))
    )
    if basename == "mcp.json" or private_env:
        return True
    if basename.endswith((".pem", ".key", ".p12", ".pfx", ".bundle.json")):
        return True
    if "storage-key" in basename:
        return True
    return any(marker in lowered for marker in ("public cloud - service deployment checklist",))


def verify_local(dist: Path, version: str) -> None:
    files = _release_files(dist)
    normalized_version = version.replace("-", "_")
    expected_prefix = f"krutrim_mcp_server-{normalized_version}"
    for artifact in files:
        if not artifact.name.startswith(expected_prefix):
            raise SystemExit(
                f"{artifact.name} does not match release version {version}"
            )
        names = _archive_names(artifact)
        forbidden = [name for name in names if _is_forbidden(name)]
        if forbidden:
            raise SystemExit(
                f"{artifact.name} contains forbidden release files: {forbidden[:10]}"
            )
        if artifact.name.endswith(".tar.gz") and not any(
            name.endswith("/uv.lock") for name in names
        ):
            raise SystemExit(f"{artifact.name} does not contain uv.lock")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fetch_release_json(repository: str, project: str, version: str) -> dict[str, Any]:
    url = f"{repository.rstrip('/')}/pypi/{project}/{version}/json"
    last_error: Exception | None = None
    for attempt in range(30):
        try:
            with urllib.request.urlopen(url, timeout=20) as response:  # noqa: S310
                return json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == 29:
                break
            time.sleep(10)
    raise SystemExit(f"release metadata was not available at {url}: {last_error}")


def verify_index(dist: Path, repository: str, project: str, version: str) -> None:
    files = _release_files(dist)
    expected = {path.name: _sha256(path) for path in files}
    metadata = _fetch_release_json(repository, project, version)
    published = {
        item["filename"]: item["digests"]["sha256"]
        for item in metadata.get("urls", [])
        if item.get("packagetype") in {"bdist_wheel", "sdist"}
    }
    if published != expected:
        raise SystemExit(
            "published artifacts do not match the build artifacts\n"
            f"expected={expected}\npublished={published}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    local = subparsers.add_parser("local", help="validate local release contents")
    local.add_argument("--dist", type=Path, required=True)
    local.add_argument("--version", required=True)

    index = subparsers.add_parser("index", help="compare local files to an index")
    index.add_argument("--dist", type=Path, required=True)
    index.add_argument("--repository", required=True)
    index.add_argument("--project", required=True)
    index.add_argument("--version", required=True)

    args = parser.parse_args()
    if args.command == "local":
        verify_local(args.dist, args.version)
    else:
        verify_index(
            args.dist,
            repository=args.repository,
            project=args.project,
            version=args.version,
        )


if __name__ == "__main__":
    main()
