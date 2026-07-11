# Security model

## Prompt-injection firewall
Agent instructions, tool payloads and context are scanned before policy evaluation. High-risk content is blocked or escalated and recorded as a security event. The included rules detect instruction overrides, secret extraction, policy bypass, sensitive-data transfer, shell injection and encoded payloads.

The deterministic firewall is a first layer, not a substitute for model-based classification, sandboxing and output validation in production.

## Credential vault
Credentials are encrypted with AES-256-GCM using a key derived from `VAULT_MASTER_SECRET`. API responses expose metadata only. During protected execution the server decrypts the selected credential in memory and injects it into the outbound request; agents never receive raw values.

For production, replace local key derivation with KMS/HSM or Rialo REX confidential key management.

## Emergency stop
A workspace stop pauses active agents, revokes every active permit, records an incident and anchors the action through the Rialo adapter. Resuming never restores revoked permits automatically.

## Network protections
Protected execution requires public HTTPS and blocks localhost, loopback, link-local and RFC1918 IPv4 targets to reduce SSRF risk.
