# Encrypted storage access-key delivery

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
