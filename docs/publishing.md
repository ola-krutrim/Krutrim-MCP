# Publishing the stdio package

This runbook covers version `1.0.4` of the local stdio package built from `main`.
It does not publish or deploy a hosted MCP server, container, HTTP transport,
ingress configuration, or hosted credentials.

A tag-triggered GitHub Actions workflow builds and validates the wheel and source
distribution, waits for protected production approval, publishes those exact
files directly to PyPI, and verifies their SHA-256 digests. Package-index
versions and files are immutable.

## One-time repository setup

1. Confirm which internal release repository will run
   `.github/workflows/release.yml`; it does not need to be exposed in package
   metadata.
2. Create a GitHub environment named `pypi`.
3. Require a trusted reviewer for the `pypi` environment and prevent self-review
   when repository policy supports it.
4. Protect `v*` release tags so only release maintainers can create or update
   them. The workflow rejects a tag whose commit is not on the default branch.
5. Verify the existing PyPI project has the correct Trusted Publisher configured.
   For a new release repository, add the publisher from the PyPI project settings. Use:

   | Setting | Value |
   | --- | --- |
   | PyPI project | `krutrim-mcp-server` |
   | GitHub owner | Actual owner of the release repository |
   | GitHub repository | Actual release repository name |
   | Workflow | `release.yml` |
   | PyPI environment | `pypi` |

   No long-lived upload token is required.
6. Confirm the distribution license and public-source approval with the owning
   team before pushing the production tag. The published wheel and source
   distribution contain readable Python source.

## Release gates

- [ ] The release commit is merged into `main`.
- [ ] `main` contains only the intended stdio product files; hosted deployment
      files are not present in the source distribution.
- [ ] `pyproject.toml` and `src/krutrim_mcp_server/_version.py` contain the same
      unused version, and `uv lock --check` passes.
- [ ] CI passes on Python 3.10, 3.11, 3.12, and 3.13.
- [ ] The required `pip-audit` gate reports no known runtime vulnerabilities.
- [ ] The release workflow produces a validated CycloneDX runtime SBOM.
- [ ] Live smoke tests pass for the supported Phase 1 resource lifecycles and
      the new Sandbox lifecycle, commands, files, ports, and proxy tools in an
      explicitly approved test account. Clean up test resources afterward.
- [ ] README, user guide, and changelog describe the shipped authentication and
      tool behavior.
- [ ] No token, key, credential bundle, private material, or local MCP
      configuration is tracked.
- [ ] The distribution license and support ownership are final.
- [ ] The Trusted Publisher and GitHub environment are configured exactly as
      described above.

## Local preflight

Build outside the repository's ignored `dist/` directory so an older artifact
cannot be mistaken for the release:

```bash
uv lock --check
uv sync --locked --extra dev --extra release --python 3.12
uv run --no-sync ruff check src tests scripts
uv run --no-sync pytest -q
uv pip check
uv export --quiet --locked --no-dev --no-emit-project \
  --output-file /tmp/krutrim-mcp-runtime-requirements.txt
uv run --no-sync pip-audit --strict --require-hashes \
  --progress-spinner off \
  --requirement /tmp/krutrim-mcp-runtime-requirements.txt
uv run --no-sync python -m build --no-isolation \
  --outdir /tmp/krutrim-mcp-1.0.4
uv run --no-sync twine check /tmp/krutrim-mcp-1.0.4/*
uv run --no-sync python scripts/verify_release_artifacts.py local \
  --dist /tmp/krutrim-mcp-1.0.4 \
  --version 1.0.4
```

The local build is diagnostic only. GitHub Actions builds the publishable files
again from the tagged `main` commit.

## Publish to PyPI

After every release gate is satisfied, create and push the matching tag from
`main`:

```bash
git switch main
git tag -s v1.0.4 -m "Release krutrim-mcp-server 1.0.4"
git push origin v1.0.4
```

The `release.yml` workflow then performs this sequence:

1. Validate that the tag is on `main` and that tag, package, and runtime versions
   all match.
2. Install the hash-locked dependency graph, run lint, unit tests, integrity
   checks, the required runtime SCA audit, package-content checks, and a
   clean-wheel stdio CLI smoke test.
3. Build one wheel and one source distribution, generate a CycloneDX runtime
   SBOM, and store the distributions and SBOM as separate GitHub Actions
   artifacts.
4. Wait for approval on the protected `pypi` environment.
5. Publish the validated artifact directly to PyPI using OIDC Trusted Publishing.
6. Compare PyPI's filenames and SHA-256 digests with the original artifact.

Approve the `pypi` job only after reviewing the completed build, test,
package-content, metadata, and stdio smoke-test results.

## Verification commands

After production publication:

```bash
uvx krutrim-mcp-server@1.0.4 --version
uvx krutrim-mcp-server@1.0.4 --list-tools
```

Then connect one supported MCP client with sandbox credentials and invoke a
read-only Cloud operation.

## Failure policy

- Never overwrite or delete a published file; indexes do not permit it.
- If PyPI received only part of a release, fix the issue and publish a new patch
  version. Do not rerun the upload with the same filenames.
- If the PyPI release is defective, yank it when appropriate and publish a new
  patch version. Do not reuse an uploaded version.
