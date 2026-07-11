# Rialo integration

AgentPermit maps naturally to Rialo's published agent-gateway model:

1. An agent invokes the AgentPermit gateway.
2. The policy engine checks identity, scopes, limits, expiry and target.
3. An approved action may execute through protected credentials.
4. The result—approved, blocked or escalated—is recorded as a signed receipt and anchored to Rialo.

The included `contracts/agent_permit.rialo` uses the public workflow shape and `AFTER wait until ... Do ...` timer pattern. It models native permit expiry without an external keeper.

## Production checklist

- Obtain current Rialo developer access, RPC URL and CDK release.
- Compile the reference program with that CDK; update syntax only where the release compiler requires it.
- Generate a dedicated devnet deployer key (`npm run keygen`) and fund it with devnet RLO.
- Set RPC method names from the current API release.
- Run `npm run deploy:rialo`; save the returned program ID as `RIALO_PROGRAM_ID`.
- Switch `RIALO_MODE=rpc`; run tests and `npm run smoke`.
- Store secrets in a managed secret store. Do not expose gateway API keys to agents.
- Replace HMAC receipt signing with KMS/HSM or REX-confidential signing for production.

No private key is included and no live-chain deployment is claimed by this repository.
