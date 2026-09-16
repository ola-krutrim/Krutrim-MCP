# Krutrim Cloud MCP user guide

## Before you begin

Sign in as the root user to obtain an access-token and refresh-token pair:

```bash
curl --location \
  'https://cloud.olakrutrim.com/iam/v1/signInAsRootUser' \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --data '{"email":"YOUR_EMAIL","password":"YOUR_PASSWORD"}'
```

For an IAM user, include the account ID:

```bash
curl --location \
  'https://cloud.olakrutrim.com/iam/v1/signInAsIAMUser' \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --data '{"accountId":"YOUR_ACCOUNT_ID","email":"YOUR_EMAIL","password":"YOUR_PASSWORD"}'
```

Use an IAM access token and refresh token from the same sign-in session.
Configure both `KRUTRIM_ACCESS_TOKEN` and `KRUTRIM_REFRESH_TOKEN` in your MCP
client using a secure secret manager or protected environment. See the
[README](../README.md) for ready-to-copy configurations.

Always pass one of the supported regions when a tool requires it:

- `In-Bangalore-1`
- `In-Hyderabad-1`

If the IAM session has MFA enabled, verify it after sign-in and before using
Cloud service tools. Use the access token returned by sign-in; it is not
rotated:

```bash
curl --location \
  'https://cloud.olakrutrim.com/iam/v1/mfa/verify' \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_ACCESS_TOKEN' \
  --data '{"otp":"YOUR_MFA_OTP"}'
```

Use a trusted host and keep the email, password, OTP, token, response,
transcripts, tickets, and logs private.

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
| Create a KPod | `list_kpod_flavors` and `list_kpod_templates` |
| Create a Sandbox | `list_sandbox_flavors` and `list_sandbox_templates` |
| Manage storage | `list_volumes`, `list_volume_types`, or `list_buckets` |
| Manage IAM | `list_iam_users`, `list_iam_groups`, and `list_iam_roles` |

For `create_sandbox`, `ttl_seconds` is optional. Omit it (or pass `null`) to
leave `ttlSeconds` out of the request; the server does not invent a TTL default.
Backend expiry behavior applies when omitted—this does not promise an indefinite
lifetime. If supplied, use an integer from 60 to 604800 seconds.
`set_sandbox_ttl` still requires an explicit value.

IAM operations require full IAM KRNs. Use the KRN returned by a list operation;
do not use a UUID, a display name, or a partial identifier.

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
| MCP server does not start | Check that both token variables are configured. |
| Refresh is rejected | Sign in again, replace both tokens, and restart the client. |
| `401` or `403` from a Cloud tool | For MFA-enabled sessions, verify MFA with the existing access token first; then verify the IAM user, service policy, and region. |
| Required identifier is rejected | List the resource again and use its complete KRN. |
| Tools are not visible | Restart the MCP client and run `--list-tools` locally. |

For encrypted object-storage access keys, see [Encrypted credential delivery](encrypted-credential-delivery.md).
