# Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`. It tests and builds the
package, publishes it to TestPyPI, waits for your approval, publishes it to PyPI,
checks the published files, and creates a GitHub Release from the changelog.
Publishing uses PyPI Trusted Publishing, so no API token is stored anywhere.

## One-time setup

1. **PyPI.** Open the `krutrim-mcp-server` project, then *Settings → Publishing*,
   and add a GitHub trusted publisher:

   | Field | Value |
   | --- | --- |
   | Owner | `ola-krutrim` |
   | Repository | `Krutrim-MCP` |
   | Workflow | `release.yml` |
   | Environment | `pypi` |

2. **TestPyPI.** Do the same at test.pypi.org for the same project name, with
   environment `testpypi`.
3. **GitHub.** In *Settings → Environments*, create:
   - `testpypi`: no protection rules.
   - `pypi`: add required reviewers (and block self-review). Its job waits for
     this approval before anything reaches PyPI.
4. Optional: add a tag ruleset for `v*` so only maintainers can create release tags.

Remove any older trusted publisher that points at a different repository.

## Release steps

1. Pick the new version `X.Y.Z`. Set it in `pyproject.toml` and
   `src/krutrim_mcp_server/_version.py`, run `uv lock`, and update the pinned
   version in `README.md`, `docs/user-guide.md`, and `tests/test_sdk_version.py`
   (`grep -rn "<old version>"` finds them).
2. Add a `## X.Y.Z — YYYY-MM-DD` section to `CHANGELOG.md`. Its text becomes the
   GitHub Release notes.
3. Merge to `main` with CI passing.
4. Tag the merged commit and push the tag:

   ```bash
   git switch main && git pull
   git tag -s vX.Y.Z -m "Release X.Y.Z"
   git push origin vX.Y.Z
   ```

5. In the workflow run, check the TestPyPI step, then approve the `pypi`
   environment. The run finishes after the digest check and the GitHub Release.

The workflow fails if the tag is not on `main`, if the tag differs from
`vX.Y.Z` in `pyproject.toml` or `_version.py`, or if the changelog has no section
for the version. To check locally:

```bash
uv run python scripts/release_check.py check --tag vX.Y.Z
```

## Dry run

*Actions → Publish stdio package → Run workflow* on a branch runs the tests and
build and publishes to TestPyPI only. It never publishes to PyPI. A version that
already exists on TestPyPI is skipped, not replaced.

## If something fails

Package indexes never accept the same file twice. If a release is partly
published or defective, fix it and release a new patch version instead of
re-running the upload.
