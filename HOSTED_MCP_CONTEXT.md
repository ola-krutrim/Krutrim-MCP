# VM Sandbox: context for the hosted MCP

Use this to add the same VM Sandbox tools to the hosted MCP server. It describes
what the local stdio server (`krutrim-mcp-server` 1.0.14, PR #9, tag `v1.0.14`)
did, so the hosted server can match its behavior. Hosted-specific wiring (auth,
transport, per-request clients) is not covered; see "Check in the hosted code".

## Summary

- 29 new tools, all named `*_vm_sandbox*` / `list_vm_sandboxes`.
- They call the native resources in `krutrim-client` **0.8.9**:
  `client.sandbox.sandboxes`, `.flavors`, `.templates`, `.operations`, `.commands`,
  `.files`, `.network`, `.ports`, `.terminal` (API prefix `/sandbox/v1`).
- Region is **`In-Hyderabad-1` only**. Other services keep both regions.
- Existing Sandbox tools are unchanged (`client.sandbox.api`, `/omni/sandbox/v1`).
- Bump the dependency to `krutrim-client>=0.8.9,<0.9`.

## Files to port

All under `src/krutrim_mcp_server/`:

| File | Role |
| --- | --- |
| `tools/vm_sandbox/_service.py` | Input validation, flavor and template checks, operation polling, and the calls to the native client. Every function returns the service response as a plain dict. |
| `tools/vm_sandbox/_support.py` | Region type, `VmSandboxNetwork` model, error mapping (`run_vm_tool`), redaction (`publish`), nonzero-exit handling (`fail_nonzero_exec`). |
| `tools/vm_sandbox/lifecycle.py` | list, describe, flavors, create, delete, start, stop, extend, resize, usage. |
| `tools/vm_sandbox/templates.py` | list, describe, create (build), delete templates. |
| `tools/vm_sandbox/operations.py` | get and wait for operations. |
| `tools/vm_sandbox/network.py` | read and replace the egress policy. |
| `tools/vm_sandbox/execution.py` | exec and asynchronous commands. |
| `tools/vm_sandbox/access.py` | ports, files, terminal ticket. |
| `tools/vm_sandbox/__init__.py` | `register(mcp)` calling each module. |
| `profiles.py` | Adds each tool name to the read-only, additive, or destructive set. A tool not in a set fails to register. |
| `server.py` | Registers `vm_sandbox` and adds the server instructions below. |
| `tests/test_vm_sandbox.py` | 78 tests. |

`_support.py` imports `redact_secrets` from `tools/sandbox/_responses.py` and
helpers from `serialize.py` and `logging_utils.py`. The hosted server needs
equivalents.

## Tools

Every tool takes `region` (only `In-Hyderabad-1`). Mutating tools also take
`confirm` (must be `true`). Mutating tools accept an optional `idempotency_key`,
except `write_vm_sandbox_file` and `create_vm_sandbox_terminal_ticket`.

| Tool | Kind | Required | Optional |
| --- | --- | --- | --- |
| `list_vm_sandboxes` | read | | status, name, limit, offset |
| `describe_vm_sandbox` | read | krn_id | |
| `list_vm_sandbox_flavors` | read | | limit, offset |
| `create_vm_sandbox` | additive | name, flavor | template, image, ttl_seconds, env, network |
| `delete_vm_sandbox` | destructive | krn_id | |
| `start_vm_sandbox` | destructive | krn_id | |
| `stop_vm_sandbox` | destructive | krn_id | |
| `extend_vm_sandbox_ttl` | destructive | krn_id, ttl_seconds | |
| `resize_vm_sandbox` | destructive | krn_id, flavor | |
| `get_vm_sandbox_usage` | read | krn_id | |
| `list_vm_sandbox_templates` | read | | limit, offset |
| `describe_vm_sandbox_template` | read | template_id | |
| `create_vm_sandbox_template` | additive | name, image | description |
| `delete_vm_sandbox_template` | destructive | template_id | |
| `get_vm_sandbox_operation` | read | operation_id | |
| `wait_vm_sandbox_operation` | read | operation_id | timeout_seconds, poll_interval_seconds |
| `get_vm_sandbox_network` | read | krn_id | |
| `update_vm_sandbox_network` | destructive | krn_id, network | |
| `exec_vm_sandbox` | destructive | krn_id, cmd | cwd, env, stdin, user, timeout_seconds |
| `create_vm_sandbox_command` | destructive | krn_id, cmd | cwd, env, user, timeout_seconds |
| `list_vm_sandbox_commands` | read | krn_id | limit, offset |
| `get_vm_sandbox_command` | read | krn_id, command_id | stdout_offset, stderr_offset, max_bytes |
| `kill_vm_sandbox_command` | destructive | krn_id, command_id | |
| `expose_vm_sandbox_port` | destructive | krn_id, port, access | |
| `list_vm_sandbox_ports` | read | krn_id | limit, offset |
| `close_vm_sandbox_port` | destructive | krn_id, port | |
| `read_vm_sandbox_file` | read | krn_id, path | |
| `write_vm_sandbox_file` | destructive | krn_id, path, content | |
| `create_vm_sandbox_terminal_ticket` | destructive | krn_id | |

`wait_vm_sandbox_operation` is read-only: it never changes anything.

## Behavior to match

**Region.** Type is `Literal["In-Hyderabad-1"]`, required, never defaulted from
configuration. Anything else (including `In-Bangalore-1` and an empty value) fails
with `VM Sandbox is only available in In-Hyderabad-1; got '<value>'.` Do not change
the shared region list used by other services.

**Create.**
- `name`: 1-64 characters, letters, digits, `.`, `_`, `-`, starting and ending with a letter or digit.
- `flavor`: exact name from `list_vm_sandbox_flavors` (catalog is read live, all pages, 200 per page). Fails if missing or ambiguous, or if a flavor exceeds 4 vCPU or 8 GiB.
- `template` and `image` are mutually exclusive. Neither means the service default template.
- `image`: at most 255 characters; Docker Hub, GHCR, Quay, ECR Public, GCR, `registry.k8s.io`, MCR, or GitLab; lowercase path components; optional tag or `sha256:` digest; no URLs.
- `ttl_seconds`: 60-604800. Omitted means the service default (one hour).
- `env`: at most 64 variables, 32 KiB total, names `[A-Za-z_][A-Za-z0-9_]*` not starting with `KRUTRIM_` or `SPACE_`. Values are redacted from the response and from error text.
- `network`: `{"egress": {"default_action": "allow"|"deny", "allow": [...], "deny": [...]}}`, at most 64 entries per list, each a domain, `*.domain`, IPv4, or IPv4 CIDR (no URLs, ports, or IPv6).
- All inputs are validated before the flavor catalog is fetched, and before any create call.

**Other calls.**
- `extend_vm_sandbox_ttl` adds 60-604800 seconds; it cannot turn expiry off.
- `resize_vm_sandbox` rechecks the flavor like create. It keeps the disk and drops running processes.
- `create_vm_sandbox_template`: name 2-40 lowercase letters, digits, or `-`, starting with a letter, not starting with `img-`; description at most 256 bytes. It first lists templates and refuses when 10 custom templates exist or 2 are still building (statuses `building`, `pending`, `provisioning`, `creating`, `queued`, `in_progress`, `build_in_progress`).
- `delete_vm_sandbox_template` reads the template first and refuses platform templates (`default_template: true`).
- `exec_vm_sandbox`: timeout 1-120 seconds, `cwd` an absolute path, `stdin` at most 1 MiB, `user` a Linux name or numeric uid. A nonzero `exit_code`, or `timed_out`, is a **tool error** that includes clipped, redacted stdout and stderr.
- `create_vm_sandbox_command`: timeout 1-604800; env names cannot start with `KRUTRIM_`.
- `get_vm_sandbox_command`: `stdout_offset` and `stderr_offset` resume reading; `max_bytes` is 1-1048576.
- Ports: 1-65535; `access` is `token` or `private`. A token URL is a credential returned only by the expose call.
- Files: absolute guest paths, no `.` or `..`; read and write are UTF-8 text up to 1 MiB; binary or non-UTF-8 files are withheld; parent directories must exist for writes. Writes and the terminal ticket are never retried and never sent with an idempotency key.
- The terminal ticket and its URL are credentials, valid for about 60 seconds.
- Pagination: `limit` 1-200, `offset` at least 0.
- IDs are rejected if they contain control characters, spaces, `/`, `?`, `#`, `\`, or a masked `:***:` account segment.

**Operations.** Create, delete, start, stop, resize, template build, and network
update return an operation id before the work finishes. `wait_vm_sandbox_operation`
polls `operations.retrieve` (default 120 s, up to 600 s; interval 0.5-60 s, default 2 s):
- `succeeded`: returns the operation.
- `failed`: tool error with the clipped error text.
- timeout: tool error saying the operation was **not cancelled**.
- any other state: tool error.

**Errors** (`run_vm_tool` in `_support.py`):
- HTTP 400, 404, 409, 422: `VM Sandbox request rejected (HTTP <status>): <service message>. Fix the request before retrying.` The message comes from the body's `message` (or `error`), redacted, whitespace-collapsed, and cut at 200 characters.
- Any other HTTP error or a connection error: `VM Sandbox request failed (<HTTP status or error type>); response details withheld. Inspect VM Sandbox state before retrying a mutation.`
- A 200 response that does not parse: `VM Sandbox returned an unexpected response; details withheld`.
- Retries are off for every call (`client.with_options(max_retries=0)`).

**Output.** Each tool returns `{"ok": true, "data": <service envelope>}` where the
envelope is the service response as received (`code`, `message`, `details`). It is
built with `model_dump(mode="json", by_alias=True, exclude_unset=True)` so unset
fields are not added and `from` in resize operations keeps its name. File reads
return `{"path", "content", "size_bytes"}`. Secret-named keys are redacted;
`ticket`, `url`, and `proxy_url` are kept (only known secrets removed).

## Server instructions to add

Add to the server's instruction text:

> VM Sandbox is only available in In-Hyderabad-1. Before create_vm_sandbox, call
> list_vm_sandbox_flavors and list_vm_sandbox_templates there and require an exact
> flavor at or below 4 vCPU and 8 GiB. Pass a template or a public image, not both.
> Expiry defaults to one hour (60–604800 seconds). extend_vm_sandbox_ttl adds time
> and cannot disable expiry. Create, delete, start, stop, resize, template build,
> and network update return an operation; poll it with wait_vm_sandbox_operation.
> A timeout does not cancel the operation. Resize keeps the disk and drops running
> processes. exec_vm_sandbox fails when exit_code is nonzero.

## Check in the hosted code

- How the SDK client is created (per request or shared) and whether `with_options(max_retries=0)` is available there.
- How read-only mode, `confirm`, and tool safety annotations are enforced, and add the 29 names to those sets.
- Whether region comes from the request or from configuration. For these tools it must be the explicit argument, limited to `In-Hyderabad-1`.
- Any tool-count assertions (the local server went from 187 to 216 tools).
- How secrets are redacted in results and logs, so env values and tickets behave as above.
- Whether the hosted gateway passes through the `x-region` and `Idempotency-Key` headers the client sets.

## Verify

1. `krutrim-client` 0.8.9 installed; `client.sandbox.sandboxes` exists and `client.sandbox.api` still works.
2. Port `tests/test_vm_sandbox.py`. It runs the real client against a mock HTTP transport, so it needs no network and no client mocking. It expects 78 passing tests.
3. Run the linter and the full suite.
4. Smoke test on the staging environment in `In-Hyderabad-1`: list flavors and templates, create, wait for the operation, exec (success and a failing command), file write and read, expose a port, create and kill a command, update network, stop, start, resize, extend, delete. This passed for all tools on the local server.

## Not covered

The console's create form has an optional boot command. The `/sandbox/v1` create
request has no such field, so `create_vm_sandbox` does not send one.
