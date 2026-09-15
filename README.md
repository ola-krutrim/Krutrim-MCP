# Krutrim Cloud MCP Server

Use Krutrim Cloud from Cursor, Claude Desktop, Claude Code, or Codex. The MCP
server provides discovery and controlled operations for VPCs, compute, storage,
networking, Kubernetes, KPods, Sandboxes, and IAM.

## Install

### Recommended: uvx

Run the released stdio package directly from PyPI without installing it into
your current Python environment:

```bash
uvx krutrim-mcp-server --version
```

### Python virtual environment

You can also install and run the package with standard Python tooling:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install krutrim-mcp-server==1.0.3
python -m krutrim_mcp_server --version
```

On Windows, activate the environment with `.venv\Scripts\activate`.

Version `1.0.3` adds guarded Sandbox tools. Use
`uvx krutrim-mcp-server@1.0.3 --version` to pin this version once it is published
on PyPI.
Future releases follow Semantic Versioning: fixes increment the patch version,
backward-compatible features increment the minor version, and breaking changes
increment the major version.

## Connect locally

### Sign in and complete MFA

Sign in as the root user to obtain the access-token and refresh-token pair:

```bash
curl --location \
  'https://cloud.olakrutrim.com/iam/v1/signInAsRootUser' \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --data '{"email":"YOUR_EMAIL","password":"YOUR_PASSWORD"}'
```

For an IAM user, use the account ID with the same flow:

```bash
curl --location \
  'https://cloud.olakrutrim.com/iam/v1/signInAsIAMUser' \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --data '{"accountId":"YOUR_ACCOUNT_ID","email":"YOUR_EMAIL","password":"YOUR_PASSWORD"}'
```

Keep the returned token pair private. If MFA is enabled, verify it with the
returned access token before configuring the MCP client. Set the returned
values in `KRUTRIM_ACCESS_TOKEN` and `KRUTRIM_REFRESH_TOKEN` through a secure
secret manager or protected environment; do not place them in shell history.

```bash
curl --location \
  'https://cloud.olakrutrim.com/iam/v1/mfa/verify' \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_ACCESS_TOKEN' \
  --data '{"otp":"YOUR_MFA_OTP"}'
```

MFA verification uses the same access token; it does not rotate the token
pair. Run both commands only from a trusted host and keep credentials, OTPs,
responses, transcripts, and logs private.

You need an IAM access token and refresh token from the same sign-in session.
Set both in the MCP client configuration; do not put token values in source
control.

```json
{
  "mcpServers": {
    "krutrim-cloud": {
      "command": "uvx",
      "args": ["krutrim-mcp-server"],
      "env": {
        "KRUTRIM_ACCESS_TOKEN": "YOUR_IAM_ACCESS_TOKEN",
        "KRUTRIM_REFRESH_TOKEN": "YOUR_IAM_REFRESH_TOKEN"
      }
    }
  }
}
```

For a Python virtual-environment installation, keep the same `env` values and
replace `command` and `args` with the virtual environment's absolute Python
path:

```json
{
  "command": "/absolute/path/to/.venv/bin/python",
  "args": ["-m", "krutrim_mcp_server"]
}
```

On Windows, use the absolute path to `.venv\Scripts\python.exe`.

Restart the client after changing its configuration. The server refreshes the
access token while the refresh token remains valid. When refresh is rejected,
sign in again and replace both values.

For Codex, add this to `~/.codex/config.toml`:

```toml
[mcp_servers.krutrim-cloud]
enabled = true
command = "uvx"
args = ["krutrim-mcp-server"]

[mcp_servers.krutrim-cloud.env]
KRUTRIM_ACCESS_TOKEN = "YOUR_IAM_ACCESS_TOKEN"
KRUTRIM_REFRESH_TOKEN = "YOUR_IAM_REFRESH_TOKEN"
```

For a Python virtual environment, set `command` to its absolute Python path and
set `args = ["-m", "krutrim_mcp_server"]` instead.

## Use the tools

Start with a read operation, select returned identifiers and regions exactly,
then confirm mutations. Examples:

```text
List my VPCs in In-Bangalore-1.
List IAM users.
Create a VPC in In-Hyderabad-1 with CIDR 10.20.0.0/24. Ask for confirmation first.
```

Mutating calls require `confirm=true`. Set `KRUTRIM_MCP_READ_ONLY=true` to block
all mutations on a local installation.

## Verify

```bash
uvx krutrim-mcp-server --list-tools
uvx krutrim-mcp-server --doctor
```

`--list-tools` verifies the installed catalog. `--doctor` verifies local
configuration; use a read-only Cloud tool such as `list_vpcs` to verify your
permissions.

## User guide

### Before you begin

Use an IAM access token and refresh token from the same sign-in session.
Configure both `KRUTRIM_ACCESS_TOKEN` and `KRUTRIM_REFRESH_TOKEN` in your MCP
client.

Always pass one of the supported regions when a tool requires it:

- `In-Bangalore-1`
- `In-Hyderabad-1`

### Recommended workflow

1. List resources before changing them.
2. Select exact identifiers returned by the list call.
3. Review the requested change.
4. Use `confirm=true` only after the review.

For example, use `list_vpcs` before `describe_vpc` or `delete_vpc`; use
`list_subnets` before VM creation; use a listed VM flavor instead of guessing
one.

### Common tasks

| Goal | Start with |
| --- | --- |
| Create a VPC | `list_vpcs`, then `create_vpc` |
| Create a VM | `list_vpcs`, `list_subnets`, and `list_compute_flavors` |
| Create a KPod | `list_kpod_flavors` and `list_kpod_templates` |
| Create a Sandbox | `list_sandbox_flavors` and `list_sandbox_templates` |
| Manage storage | `list_volumes`, `list_volume_types`, or `list_buckets` |
| Manage IAM | `list_iam_users`, `list_iam_groups`, and `list_iam_roles` |

IAM operations require full IAM KRNs. Use the KRN returned by a list operation;
do not use a UUID, a display name, or a partial identifier.

### Safety controls

- Mutations require `confirm=true`.
- `KRUTRIM_MCP_READ_ONLY=true` blocks every mutation.
- Do not retry a timed-out create immediately. List by name or identifier first
  to determine whether the resource was created.
- For destructive operations, inspect the selected identifier before confirming.
- The `create_iam_user` password is sensitive. Use it only from a trusted MCP
  host because tool-call transcripts and host logs are outside this package's
  control. Use the approved encrypted credential-delivery or out-of-band
  process where applicable.

### Troubleshooting

| Problem | What to do |
| --- | --- |
| MCP server does not start | Check that both token variables are configured. |
| Refresh is rejected | Sign in again, replace both tokens, and restart the client. |
| `401` or `403` from a Cloud tool | For MFA-enabled sessions, verify MFA with the existing access token first; then verify the IAM user, service policy, and region. |
| Required identifier is rejected | List the resource again and use its complete KRN. |
| Tools are not visible | Restart the MCP client and run `--list-tools` locally. |

For object-storage access keys, follow
[Encrypted storage access-key delivery](#encrypted-storage-access-key-delivery).

## Encrypted storage access-key delivery

`create_storage_access_key` delivers a ciphertext bundle, not a plaintext
secret. Generate a recipient key on the device that will use the key:

```bash
krutrim-mcp-credentials init
```

Use the printed `public_key` and `fingerprint` in the MCP request. Ask the
client to show the name, region, and fingerprint before you confirm creation.

After the tool returns a bundle, decrypt it locally:

```bash
krutrim-mcp-credentials decrypt \
  --bundle /path/to/storage-key.bundle.json \
  --output ~/.config/krutrim-mcp/storage-key.json
```

Keep the private key and decrypted output on your device. Do not paste either
into an MCP prompt, repository, ticket, or chat message. If creation times out,
list existing keys before retrying.
