# Changelog

## 1.0.5 — 2026-09-17

Simplify authentication and improve VM networking.

- Authenticate with a single `KRUTRIM_API_KEY`; token pairs are no longer used.
- Credentials are redacted from tool output and logs.
- Subnet discovery works again; VM creation is no longer blocked by empty subnet lists.
- New: allocate a floating IP (explicit approval required) and delete a subnet.
- VM creation waits up to 10 minutes by default (`KRUTRIM_CREATE_TIMEOUT_SECONDS`);
  timeout messages now warn before retrying to avoid duplicate VMs.
- `list_security_groups` accepts `vpc_id` (`vpc_krn` still works);
  `describe_instance` returns `ip_addresses` as structured data.
- Sandbox listings show availability and status; expiry defaults to one hour
  (configurable from 1 minute to 7 days).
- Update the bundled Krutrim SDK to 0.6.2 (Sandbox catalog and command fixes);
  Sandbox flavor listings keep the same output shape.

## 1.0.4 — 2026-09-16

Fix Sandbox creation and improve setup options.

- Fix flavor selection errors that blocked Sandbox creation.
- Hide unreliable flavor availability labels from discovery results.
- Make creation TTL optional; use backend expiry behavior when omitted.

## 1.0.3 — 2026-09-15

Add guarded Sandbox support to the local stdio package.

- Upgrade to `krutrim-client>=0.6.1,<0.7`.
- Add 19 Sandbox tools for discovery, lifecycle, commands, files, ports, and
  HTTP proxying, bringing the supported catalog to 157 tools.
- Require explicit creation choices, mutation confirmation, and separate approval
  for public ports; disable automatic retries for Sandbox mutations.
- Validate responses, redact sensitive content, and bound UTF-8 file transfers
  without accessing the MCP host filesystem.
- Add SDK compatibility and security regression tests; update package documentation.

## 1.0.2 — 2026-08-21

Update package documentation.

- Refresh README installation commands and pinned-version examples.
- Point the package documentation link to the MCP overview.

## 1.0.1 — 2026-08-21

Update SDK and dependency compatibility.

- Upgrade to `krutrim-client>=0.6.0,<0.7`.
- Replace the Pydantic 2.11.0 pin with `pydantic>=2.12.0,<3`.
- Refresh the dependency lockfile.

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
