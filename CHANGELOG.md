# Changelog

## 1.0.14 — 2026-11-12

- Added VM Sandbox as a separate service from Sandbox. Existing Sandbox tools
  are unchanged and still call `/omni/sandbox/v1` through `krutrim-client` 0.8.8.
  VM Sandbox tools call `/sandbox/v1`. The staging client that implements that
  API removes `client.sandbox.api`, so this server uses a direct HTTP adapter
  instead of replacing the pinned client.
- New tools: `list_vm_sandboxes`, `describe_vm_sandbox`, `create_vm_sandbox`,
  `delete_vm_sandbox`, `start_vm_sandbox`, `stop_vm_sandbox`,
  `extend_vm_sandbox_ttl`, `resize_vm_sandbox`, `get_vm_sandbox_usage`,
  `list_vm_sandbox_flavors`, `list_vm_sandbox_templates`,
  `describe_vm_sandbox_template`, `create_vm_sandbox_template`,
  `delete_vm_sandbox_template`, `get_vm_sandbox_operation`,
  `wait_vm_sandbox_operation`, `get_vm_sandbox_network`,
  `update_vm_sandbox_network`, `exec_vm_sandbox`, `create_vm_sandbox_command`,
  `list_vm_sandbox_commands`, `get_vm_sandbox_command`, `kill_vm_sandbox_command`,
  `expose_vm_sandbox_port`, `list_vm_sandbox_ports`, `close_vm_sandbox_port`,
  `read_vm_sandbox_file`, `write_vm_sandbox_file`, and
  `create_vm_sandbox_terminal_ticket`.
- `exec_vm_sandbox` treats a nonzero `exit_code` as a failure even when HTTP
  succeeds. Create, delete, start, stop, resize, template build, and network
  update return an operation; `wait_vm_sandbox_operation` polls it and a timeout
  does not cancel the server operation. `extend_vm_sandbox_ttl` adds time and
  cannot disable expiry. Flavors above 4 vCPU or 8 GiB are rejected. Custom
  templates are limited to 10, with 2 builds at a time.
- The console's optional boot command is not part of the `/sandbox/v1` create
  body in the staging client, so `create_vm_sandbox` does not send one.

## 1.0.13 — 2026-10-26

- Updated to `krutrim-client` 0.8.8.
- New `update_sandbox_network_policy` (full replacement) and `patch_sandbox_network_policy`
  (partial update with outbound-domain add/remove) tools. The service now enforces
  Sandbox network policy; responses report `enforcement_status`.
- `set_sandbox_ttl` accepts `0` to disable expiry (the Sandbox then keeps billing until
  deleted).
- New `upload_image_s3` tool: import a VM image (qcow2, vhd, vhdx, vmdk, raw, iso) into
  Krutrim Cloud from an HTTP(S) URL.
- `create_asg` and `create_launch_template` are enabled again. `krutrim-client` 0.8.7
  crashed while looking up the VPC network for both calls; the server now performs that
  lookup itself.
- New load balancer tools: `list_load_balancers`, `describe_load_balancer`,
  `get_load_balancer_payload`, `get_load_balancer_task_status`, `create_load_balancer`,
  `update_load_balancer`, `delete_load_balancer`, and target group tools
  `list_target_groups`, `list_target_group_names`, `get_detailed_target_groups`,
  `create_target_group`, `update_target_group`, `delete_target_group`.
- New certificate manager tools: `list_certificates`, `describe_certificate`,
  `get_expiring_certificates`, `get_certificate_tag_value`, `import_certificate`,
  `update_certificate`, `delete_certificate`, `add_certificate_tags`.

## 1.0.12 — 2026-10-23

- New `set_sandbox_flavor` tool: resize a running Sandbox to another active flavor
  without restarting it (CPU and memory only; GPU changes are rejected).
- Fixed `set_sandbox_ttl` failing with HTTP 404 against the current Sandbox API.
- `create_sandbox` rejects `sandbox_name` longer than 28 characters up front,
  matching the service limit.
- Updated to `krutrim-client` 0.8.7.

## 1.0.11 — 2026-10-16

- `create_instance` accepts optional `tags` (a list of strings or key/value objects) to
  attach to the VM at creation.
- Updated `mcp` to 1.30.0 (security fix).

## 1.0.10 — 2026-10-09

- `create_sandbox` accepts an optional `image_uri` to run your own container
  image (Bring Your Own Container), and optional `labels` (key/value tags).
  Custom images must be public, `linux/amd64`, and bundle Krutrim's
  `sandbox-agent`; see the
  [BYOC guide](https://docs.cloud.olakrutrim.com/basics/core-infrastructure/sandbox/bring-your-own-container-byoc).
- `list_sandboxes` can filter by `labels`.
- Sandbox request validation errors (HTTP 400/422) now include the backend's
  reason, e.g. an unknown or invalid field, instead of a generic failure.
- `delete_sandbox` notes that deletion is asynchronous; a deleted sandbox may
  briefly still appear in listings.
- Updated to `krutrim-client` 0.8.4.

## 1.0.9 — 2026-09-28

- `create_sandbox` fixed to match the current Sandbox create API: the backend
  no longer accepts template selection (`template_id`/`template_name` removed;
  the runtime template is chosen server-side), and `environment_variables`
  values are now base64-encoded on the wire as the backend requires. Creation
  previously failed with `400 unknown field "templateName"` for every request.

## 1.0.8 — 2026-09-24

- New `get_instance_task_status` tool: poll the task_id returned by
  `create_instance` (the existing `get_vpc_task_status` only tracks VPC
  creation and cannot resolve instance task ids).
- `create_instance` guidance and timeout error now point to
  `get_instance_task_status` first, then `search_instances`.
- krutrim-client SDK 0.6.2 → 0.6.4.

## 1.0.7 — 2026-09-21

- `delete_ssh_key` accepts the key's `uuid` or its KRN (even masked); the API
  does not populate `id`, and listings now document `uuid` as the identifier.
- All 159 tools reject masked `:***:` KRNs before any API call (wire-level
  guard) with a clear fix-it message instead of an opaque API error.
- `create_instance` timeout guidance and instance-listing docs now point to
  `search_instances`, which shows building and failed instances (with
  failure_reason) that `list_instances` may omit.

## 1.0.6 — 2026-09-18

- Security-group rules accept `protocol="icmp"` without ports (allows ping
  without opening all protocols); explicit ICMP type/code values still pass through.

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
