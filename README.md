# Krutrim Cloud MCP Server

Use Krutrim Cloud from VS Code, Cursor, Claude Desktop, Claude Code, or Codex.
The local stdio server provides 159 tools for discovery and controlled operations
across compute, networking, storage, Kubernetes, KPods, Sandboxes, and IAM.

## Install

### Recommended: uvx

Run the pinned package without installing it into your current Python environment:

```bash
uvx krutrim-mcp-server@1.0.5 --version
```

### Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install krutrim-mcp-server==1.0.5
python -m krutrim_mcp_server --version
```

On Windows, activate with `.venv\Scripts\activate`.

## Connect locally

Create a key in **Krutrim Cloud Console → Administration → API keys → Create API Key**.
Configure `KRUTRIM_API_KEY` with the raw key, without a `Bearer` prefix or surrounding
spaces. Keep keys private and restart the MCP client after changing the key.

### Create an API key with curl or Postman

Use `POST https://cloud.olakrutrim.com/iam/v1/apikey` with an authorized Cloud
Console access token. This token is for key creation only; MCP uses the resulting
API key, not the Console token.

With `KRUTRIM_CONSOLE_ACCESS_TOKEN` set privately:

```bash
curl --request POST 'https://cloud.olakrutrim.com/iam/v1/apikey' \
  --header "Authorization: Bearer ${KRUTRIM_CONSOLE_ACCESS_TOKEN}" \
  --header 'Content-Type: application/json' \
  --header 'x-region: In-Hyderabad-1' \
  --data '{"apiKeyName":"mcp-key"}'
```

In Postman, import this curl request, set **Authorization → Bearer Token** to your
Console access token, and send the JSON body. Browser cookies are not needed.
Store the returned `secretKey` securely and use it as `KRUTRIM_API_KEY`.

### VS Code

Use `.vscode/mcp.json`; the masked prompt keeps the key out of the file:

```json
{
  "servers": {
    "krutrim-cloud": {
      "type": "stdio",
      "command": "uvx",
      "args": ["krutrim-mcp-server@1.0.5"],
      "env": {
        "KRUTRIM_API_KEY": "${input:krutrim-api-key}"
      }
    }
  },
  "inputs": [
    {
      "id": "krutrim-api-key",
      "type": "promptString",
      "description": "Krutrim Cloud API key",
      "password": true
    }
  ]
}
```

### Cursor or Claude Desktop

Use your client's private MCP configuration:

```json
{
  "mcpServers": {
    "krutrim-cloud": {
      "command": "uvx",
      "args": ["krutrim-mcp-server@1.0.5"],
      "env": {
        "KRUTRIM_API_KEY": "YOUR_KRUTRIM_API_KEY"
      }
    }
  }
}
```

### Codex

Add this to your private `~/.codex/config.toml`:

```toml
[mcp_servers.krutrim-cloud]
enabled = true
command = "uvx"
args = ["krutrim-mcp-server@1.0.5"]

[mcp_servers.krutrim-cloud.env]
KRUTRIM_API_KEY = "YOUR_KRUTRIM_API_KEY"
```

For a virtual environment or local checkout, replace `command` with the absolute
path to `.venv/bin/python` and `args` with `["-m", "krutrim_mcp_server"]`.
On Windows, use `.venv\Scripts\python.exe`. No environment-cleanup wrapper is needed.

## Use the tools

List resources, select exact identifiers and a supported region
(`In-Bangalore-1` or `In-Hyderabad-1`), then confirm changes. Examples:

```text
List my VPCs in In-Bangalore-1.
List IAM users.
Show Sandbox flavors and templates before creating a Sandbox.
```

| Goal | Start with |
| --- | --- |
| Create a VPC | `list_vpcs`, then `create_vpc` |
| Create a VM | `list_vpcs`, `list_subnets`, and `list_compute_flavors` |
| Allocate a floating IP | `describe_vpc`, then `create_floating_ip` |
| Create a KPod | `list_kpod_flavors` and `list_kpod_templates` |
| Create a Sandbox | `list_sandbox_flavors` and `list_sandbox_templates` |
| Manage storage | `list_volumes`, `list_volume_types`, or `list_buckets` |
| Manage IAM | `list_iam_users`, `list_iam_groups`, and `list_iam_roles` |

Mutations require `confirm=true`. Floating-IP allocation also requires
`allow_public_ip=true`. Set `KRUTRIM_MCP_READ_ONLY=true` to block mutations.
After a create timeout, check for the resource before retrying; new VMs can take
several minutes to appear in listings.

## Verify

With the API key configured privately:

```bash
uvx krutrim-mcp-server@1.0.5 --list-tools
uvx krutrim-mcp-server@1.0.5 --doctor
```

`--doctor` checks local configuration, not Cloud authentication. Use a read-only
Cloud tool such as `list_vpcs` to verify access.

## User guide

See the [user guide](https://docs.cloud.olakrutrim.com/mcp/overview) for configuration details, safety
controls, and troubleshooting.

## Encrypted storage access-key delivery

`create_storage_access_key` returns an encrypted bundle, not a plaintext secret.
Generate a recipient key with `krutrim-mcp-credentials init`, then follow
[Encrypted credential delivery](docs/encrypted-credential-delivery.md) to decrypt
it on your device. Never share the private key or decrypted output.
