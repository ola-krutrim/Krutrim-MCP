# Changelog

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
