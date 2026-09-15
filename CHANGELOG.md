# Changelog

## 1.0.3 — Unreleased

### Added

- Add 19 Sandbox MCP tools, expanding the supported catalog from 138 to 157:
  template/flavor discovery, list/describe/create/delete, TTL updates, command
  execution, file inspection and changes, port management, and HTTP proxying.
- Require explicit region, template, flavor, and TTL choices for Sandbox creation.
  Validate the selected template and active flavor against the live Sandbox
  catalogs; return asynchronous acceptance without polling or automatic cleanup.
- Require confirmation and writable mode for all mutations, including commands
  and every proxy method. Opening a port also requires explicit public-exposure
  approval. Disable automatic SDK retries for Sandbox mutations.
- Add path/identifier validation, bounded UTF-8 file transfer (1 MiB), credential
  redaction, and suppression of sensitive SDK error bodies. File operations never
  access the MCP host filesystem.
- Limit proxy requests to Sandbox-relative paths and JSON/UTF-8 bodies; reject
  arbitrary URLs, custom headers, query strings, encoded paths, and redirects.
- Add offline real-SDK wire-contract tests, MCP protocol round-trip and safety
  tests, and a Sandbox user guide documenting the supported scope and limits.

### Changed

- Require `krutrim-client>=0.6.1,<0.7` and lock SDK 0.6.1.
- Retain existing infrastructure compatibility adapters and authentication behavior.

### Security

- Redact supplied environment values and uploaded content before generic secret
  filtering, including overlapping matches and secrets echoed in response keys.
- Parse Sandbox template JSON even when returned as `text/plain`, preserving
  structured environment redaction.
- Strictly validate SDK responses without emitting warnings containing backend
  values; withhold sensitive validation and serialization diagnostics.
- Reject failed application-level envelopes even on HTTP 200, including file
  uploads and port closure, while retaining bodyless HTTP 204 success.

### Release verification

- Local offline tests pass on Python 3.10–3.13: 1,012 passed and 2 skipped per
  interpreter. Independent security review, Ruff, builds, and artifact checks pass.
- Live Sandbox lifecycle verification and the supported-Python CI matrix remain
  release gates; offline transport tests do not prove Cloud service availability.

## 1.0.0 — 2026-08-20

Initial stable package build of the local stdio `krutrim-mcp-server`.

- Run Krutrim Cloud MCP locally from Cursor, Claude Desktop, Claude Code,
  Codex, and other compatible MCP clients.
- Authenticate with an IAM access-token and refresh-token pair, with in-process
  access-token renewal while the refresh token remains valid.
- Expose the unified supported infrastructure catalog with explicit regions,
  confirmation-gated mutations, read-only enforcement, identity preflights,
  secret redaction, and zero automatic retries for non-idempotent creates.
- Cover VPC, compute, networking, block and object storage, DNS, IAM,
  Kubernetes, and guarded KPod operations supported by `krutrim-client` 0.5.9.
- Deliver newly created object-storage credentials as recipient-encrypted
  bundles rather than plaintext secrets.
