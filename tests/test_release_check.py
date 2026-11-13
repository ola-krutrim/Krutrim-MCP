"""Release version and changelog checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import release_check


def _project(
    root: Path,
    *,
    package="1.2.3",
    runtime="1.2.3",
    changelog="## 1.2.3 — x\n\n- Item.\n",
):
    (root / "src/krutrim_mcp_server").mkdir(parents=True)
    (root / "pyproject.toml").write_text(f'[project]\nname = "x"\nversion = "{package}"\n')
    (root / "src/krutrim_mcp_server/_version.py").write_text(f'__version__ = "{runtime}"\n')
    (root / "CHANGELOG.md").write_text("# Changelog\n\n" + changelog)
    return root


def test_matching_tag_and_versions_pass(tmp_path):
    assert release_check.check("v1.2.3", _project(tmp_path)) == "1.2.3"


def test_branch_runs_without_a_tag(tmp_path):
    assert release_check.check(None, _project(tmp_path)) == "1.2.3"


@pytest.mark.parametrize("tag", ["v1.2.4", "1.2.3", "v1.2", ""])
def test_wrong_tag_fails(tmp_path, tag):
    with pytest.raises(SystemExit, match="expected tag v1.2.3"):
        release_check.check(tag, _project(tmp_path))


def test_runtime_and_package_versions_must_match(tmp_path):
    with pytest.raises(SystemExit, match="runtime version 1.2.2"):
        release_check.check("v1.2.3", _project(tmp_path, runtime="1.2.2"))


def test_changelog_needs_a_section_for_the_version(tmp_path):
    with pytest.raises(SystemExit, match="no section for 1.2.3"):
        release_check.check("v1.2.3", _project(tmp_path, changelog="## 1.2.2 — x\n\n- Old.\n"))


def test_notes_stop_at_the_next_heading(tmp_path):
    root = _project(
        tmp_path, changelog="## 1.2.3 — x\n\n- New.\n- Newer.\n\n## 1.2.2 — y\n\n- Old.\n"
    )
    assert release_check.changelog_notes("1.2.3", root) == "- New.\n- Newer."


def test_repository_versions_are_consistent():
    version = release_check.check(None)
    assert release_check.check(f"v{version}") == version
    assert release_check.changelog_notes(version)
