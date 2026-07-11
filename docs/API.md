# AgentPermit API

All write endpoints require `Authorization: Bearer $AGENTPERMIT_ADMIN_TOKEN`.

## Core
- `GET /api/health` — service, emergency state and Rialo adapter health
- `GET /api/summary` — dashboard counters
- `GET /api/agents|policies|permits|receipts|approvals|securityEvents|incidents`
- `POST /api/permits` — issue a scoped permit
- `POST /api/permits/:id/revoke` — revoke a permit
- `POST /api/actions/authorize` — firewall scan, policy evaluation, optional protected action, signed receipt and Rialo anchor
- `GET /api/receipts/:id/verify` — independently verify a receipt body and signature

## Visual policy builder
- `POST /api/policies` — publish a reusable policy with scope, budget, rate and condition blocks

## Human approval
- `POST /api/approvals/:id/approve`
- `POST /api/approvals/:id/deny`

## Credential vault
- `GET /api/credentials` — metadata only; encrypted values are never returned
- `POST /api/credentials` — encrypt and store bearer/API-key/header credentials
- `DELETE /api/credentials/:id` — revoke a credential

## Security
- `GET /api/security/rules` — active prompt-injection rules
- `POST /api/security/scan` — scan arbitrary content or tool payloads

## Emergency controls
- `POST /api/emergency-stop` — stop the workspace or one agent and revoke affected permits
- `POST /api/emergency-resume` — resume paused agents; revoked permits remain revoked

Example action request:

```json
{
  "permitId": "permit_deploy",
  "agentId": "agent_1",
  "scope": "deploy:staging",
  "target": "staging",
  "amount": 10,
  "input": "Deploy release 2.1 to staging",
  "execute": false
}
```
