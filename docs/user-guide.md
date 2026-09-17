# Krutrim Cloud MCP user guide

## Before you begin

These instructions describe **version 1.0.5** and its API-key-only configuration.
Install the release when available on PyPI, or install this checkout during
release preparation. See [installation](../README.md#install) and
[client configuration](../README.md#connect-locally).

Create a key in **Krutrim Cloud Console → Administration → API keys → Create API Key**,
or use the [curl/Postman endpoint](../README.md#create-an-api-key-with-curl-or-postman).
Set one `KRUTRIM_API_KEY` privately in your MCP server environment, using
a secret manager or protected client configuration. Never put actual keys in
prompts, shell history, source control, tickets, transcripts, or logs.

A valid API key works even if `KRUTRIM_ACCESS_TOKEN` or `KRUTRIM_REFRESH_TOKEN` is
inherited from your shell or editor; those variables are ignored, not used as a
fallback. No `env -u` wrapper is needed. Legacy tokens alone remain unsupported.
Supply the exact opaque key, not a JWT or a `Bearer`-prefixed value. Whitespace, control
characters, and non-ASCII characters are rejected. SDK-compatible API-key aliases
remain supported; prefer one `KRUTRIM_API_KEY` to avoid conflicting values.

The gateway deployment selected by `KRUTRIM_BASE_URL` must support API-key
authentication for the requested Cloud services. The SDK sends the key unchanged
in the Bearer Authorization header. The MCP server does not sign in, exchange the
key for tokens, or refresh tokens. After key rotation, update the private setting
and restart the MCP client to start a new server process.

Always pass one of the supported regions when a tool requires it:

- `In-Bangalore-1`
- `In-Hyderabad-1`

### Check local configuration

From the installed Python environment, with the key set privately:

```bash
.venv/bin/python -m krutrim_mcp_server --list-tools
.venv/bin/python -m krutrim_mcp_server --doctor
```

Use `.venv\Scripts\python.exe` on Windows. `--doctor` makes no network request and
does not initialize the SDK. It always reports `authentication_verified=false`;
local readiness does not prove gateway authentication or IAM permissions. Without
a key, it reports unready and exits 1, and SDK-backed calls fail. Only an authorized
Cloud request (for example, read-only `list_vpcs` with an explicit region) can
verify remote access.

## Recommended workflow

1. List resources before changing them.
2. Select exact identifiers returned by the list call.
3. Review the requested change.
4. Use `confirm=true` only after the review.

For example, use `list_vpcs` before `describe_vpc` or `delete_vpc`; use
`list_subnets` before VM creation; use a listed VM flavor instead of guessing
one.

## Common tasks

| Goal | Start with |
| --- | --- |
| Create a VPC | `list_vpcs`, then `create_vpc` |
| Create a VM | `list_vpcs`, `list_subnets`, and `list_compute_flavors` |
| Allocate a floating IP | `describe_vpc`, then `create_floating_ip` |
| Create a KPod | `list_kpod_flavors` and `list_kpod_templates` |
| Create a Sandbox | `list_sandbox_flavors` and `list_sandbox_templates` |
| Manage storage | `list_volumes`, `list_volume_types`, or `list_buckets` |
| Manage IAM | `list_iam_users`, `list_iam_groups`, and `list_iam_roles` |

**Sandbox availability:** `list_sandbox_flavors` shows backend-reported availability
and flavor status when present, alongside names, resources, and pricing. These
values are a live snapshot, not a capacity reservation. Missing availability means
unknown. Creation rechecks the selected flavor's active status before submitting.

**Expiry (TTL):** Specify how long the sandbox should remain active. If not
specified, the default is **one hour (3600 seconds)**. Supported duration:
**1 minute to 7 days (60–604800 seconds)**. Review this expiry before confirming
creation.

For `create_sandbox`, `ttl_seconds` is optional. Omit it (or pass `null`) to
leave `ttlSeconds` out of the request and let the backend apply its one-hour
default. To choose a different duration, supply an integer number of seconds.
`set_sandbox_ttl` requires an explicit value within the same supported range.

IAM operations require full IAM KRNs. Use the KRN returned by a list operation;
do not use a UUID, a display name, or a partial identifier.

## VM creation and public IPs

VM creation waits up to 10 minutes by default. Set `KRUTRIM_CREATE_TIMEOUT_SECONDS`
to change this timeout. A timeout does not prove creation failed: check
`list_instances` before retrying, allowing several minutes for new VMs to appear.

`create_floating_ip` allocates a billable public address and requires both
`allow_public_ip=true` and `confirm=true`. Use full, unmasked VPC, network, and
subnet KRNs. If a listing masks the account segment as `:***:`, obtain the correct
account UUID before submitting it. Inspect existing allocations after a failed
create request before retrying.

## Safety controls

- Mutations require `confirm=true`.
- `KRUTRIM_MCP_READ_ONLY=true` blocks every mutation.
- Do not retry a timed-out create immediately. List by name or identifier first
  to determine whether the resource was created.
- For destructive operations, inspect the selected identifier before confirming.
- The `create_iam_user` password is sensitive. Use it only from a trusted MCP
  host because tool-call transcripts and host logs are outside this package's
  control. Use the approved encrypted credential-delivery or out-of-band
  process where applicable.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| MCP server does not start | Use version 1.0.5 and set a valid `KRUTRIM_API_KEY` privately; inherited token variables do not need cleanup. |
| API key is revoked or rotated | Replace the key privately and restart the MCP client; there is no token refresh. |
| `401` or `403` from a Cloud tool | Verify API-key support on the configured gateway, key validity, IAM permissions, service policy, and region. |
| Required identifier is rejected | List the resource again and use its complete KRN. |
| Tools are not visible | Restart the MCP client and run `--list-tools` locally. |

For encrypted object-storage access keys, see [Encrypted credential delivery](encrypted-credential-delivery.md).
