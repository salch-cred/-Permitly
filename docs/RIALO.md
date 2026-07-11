# Rialo integration — AgentPermit v4

AgentPermit v4 is a multi-tenant governance contract for autonomous AI agents on Rialo.
It extends the original agent-gateway model with enterprise-grade controls.

## Architecture

```
Agent → Permit Gateway → Policy Engine → Multi-sig → Staking → Receipt → Rialo Anchor
                          │
                          ├─ Role-based scope check
                          ├─ Budget & rate-limit check
                          ├─ Stake sufficiency check
                          └─ Delegation resolution
```

## v4 Contract Features

| Feature | Description |
|---------|-------------|
| **Multi-sig Guardians** | N-of-M guardian approval for high-risk actions |
| **Delegation** | Agents can delegate authority with scoped, time-bound permits |
| **Role-based Policies** | Roles define scope roots, budgets, and capabilities |
| **Staking / Slashing** | Agents stake tokens; violations trigger slashing |
| **Timelock** | Admin actions have a configurable delay before execution |
| **Policy Migration** | Live migration of permits between policy versions |
| **Freeze / Unfreeze** | Emergency freeze of individual permits |
| **Permit Expiry** | Native `AFTER wait until ... Do ...` timer pattern |
| **Rialo Cruise ⛽** | Gas-less meta-transactions — users don't need RIALO tokens |

## Rialo Cruise: Gas-less Transactions

Rialo Cruise allows users to interact with the AgentPermit contract **without holding RIALO tokens**. The Permitly backend (relayer) pays all gas fees.

### How it works

```
User (Agent Controller)                    Permitly Backend (Relayer)              Rialo Devnet
         │                                          │                                  │
         │  1. Create meta-tx payload               │                                  │
         │     (kind, params, nonce)                │                                  │
         │                                          │                                  │
         │  2. Sign payload off-chain               │                                  │
         │     (Ed25519 signature)                  │                                  │
         │                                          │                                  │
         │────────────────── 3. Submit ────────────►│                                  │
         │     { payload, signature }               │                                  │
         │                                          │                                  │
         │                                          │── 4. Relay to Rialo ────────────►│
         │                                          │     (sponsored_issue_permit,     │
         │                                          │      sponsored_authorize, etc.)  │
         │                                          │◄── txHash ──────────────────────│
         │                                          │                                  │
         │◄──────────── 5. txHash ─────────────────│                                  │
         │                                          │                                  │
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cruise/status` | GET | Check if Cruise is enabled |
| `/api/cruise/nonce/:signer` | GET | Get current nonce for a signer |
| `/api/cruise/sponsored-permit` | POST | Issue a permit without user paying gas |
| `/api/cruise/relay` | POST | Submit a signed meta-transaction |

### SDK Usage (JavaScript)

```javascript
import { RialoAdapter, Keypair } from '@rialo/ts-cdk';

const rialo = new RialoAdapter({ mode: 'rpc' });

// 1. Get current nonce for the signer
const nonce = await rialo.getNonce(signerAddress);

// 2. Create meta-tx payload
const payload = rialo.createMetaTxPayload(
  'sponsored_authorize',
  { permitId, actionHash, amount, receiptId, previousHash: '' },
  signerAddress,
  nonce,
  300  // estimated gas
);

// 3. Sign with user's keypair
const signature = await rialo.signMetaTxPayload(payload, userKeypair);

// 4. Submit to relay
const result = await rialo.relayMetaTx(
  payload,
  signature,
  'https://api.permitly.dev/api/cruise/relay'
);
```

### Contract Functions

| Function | Description |
|----------|-------------|
| `set_relayer` | Set the authorized relayer address (owner only) |
| `set_cruise_budget` | Set total RIALO budget for gas sponsorship |
| `verify_meta_tx` | Verify a signed meta-transaction (relayer only) |
| `sponsored_issue_permit` | Issue a permit with gas paid by relayer |
| `sponsored_authorize` | Authorize an action with gas paid by relayer |
| `sponsored_record_denial` | Record a denial with gas paid by relayer |

### Security

- **Nonce-based replay protection**: Each signer has a monotonically increasing nonce
- **Payload expiry**: Meta-txs expire after 1 hour
- **Relayer authorization**: Only the configured relayer can submit meta-txs
- **Budget cap**: Total gas sponsorship is limited by `cruise_budget`
- **Signature verification**: All meta-txs require the user's Ed25519 signature

## Contract source

`contracts/agent_permit.rialo` — the full v4 governance program.

### State

- `owner`, `globally_paused` — global controls
- `agents` — registered agents with role, stake, violation count
- `delegations` — scoped, time-bound delegate authorizations
- `policies` — policy definitions with min_approvals and timelock flags
- `roles` — role definitions with scope roots, budgets, delegation/approval permissions
- `permits` — active/revoked/expired/frozen permits
- `guardians`, `approvals`, `guardian_votes` — multi-sig approval system
- `stakes`, `slash_records` — staking and slashing ledger
- `receipts` — hash-chained audit trail
- `credential_hashes` — credential metadata registry
- `timelock_delay`, `pending_admin_actions` — timelock system
- `policy_migrations` — live policy migration tracking
- `meta_tx_nonces`, `meta_tx_relayer`, `sponsored_permits`, `cruise_budget`, `cruise_spent` — Rialo Cruise gas-less tx system

### Key functions

**Admin:**
- `transfer_ownership`, `add_guardian`, `remove_guardian`, `set_timelock_delay`
- `schedule_timelock_action`, `execute_timelock_action`, `cancel_timelock_action`
- `emergency_stop`, `emergency_resume`
- `set_relayer`, `set_cruise_budget`

**Agents & Delegation:**
- `register_agent`, `deactivate_agent`, `set_agent_role`
- `create_delegation`, `revoke_delegation`

**Roles & Policies:**
- `create_role`, `update_role`, `deactivate_role`
- `publish_policy`, `deprecate_policy`
- `start_policy_migration`, `complete_policy_migration`

**Permits:**
- `issue_permit`, `migrate_permit`, `freeze_permit`, `unfreeze_permit`, `revoke_permit`

**Authorization:**
- `authorize_and_consume` — checks sender (controller or delegate), policy, scope, budget, stake
- `request_approval` — creates multi-sig approval with N-of-M threshold
- `cast_vote` — guardian votes; auto-decides when threshold reached
- `record_denial` — records blocked actions with reason codes

**Rialo Cruise (Gas-less):**
- `sponsored_issue_permit` — issue a permit with relayer paying gas
- `sponsored_authorize` — authorize an action with relayer paying gas
- `sponsored_record_denial` — record a denial with relayer paying gas
- `verify_meta_tx` — verify signed meta-transaction
- `consume_nonce` — prevent replay attacks

**Staking:**
- `deposit_stake`, `withdraw_stake`, `slash_stake`

**Credentials:**
- `register_credential_hash`

### Events

35+ events covering every state change: `AgentRegistered`, `DelegationCreated`, `RoleCreated`, `PolicyPublished`, `PermitIssued`, `PermitMigrated`, `PermitFrozen`, `ApprovalRequested`, `VoteCast`, `ApprovalDecided`, `StakeDeposited`, `StakeSlashed`, `TimelockScheduled`, `TimelockExecuted`, `PolicyMigrationStarted`, `PolicyMigrationCompleted`, `MetaTxRelayed`, `CruiseBudgetSet`, `CruiseBudgetSpent`, `RelayerSet`, `SponsoredPermitIssued`, and more.

## Deployment status

**AgentPermit v4 is live on Rialo devnet:**
- **Program ID:** `2RdznG7VJYGWaDyfZAWcuCBCbQ1cknMuZdDKfSVvTJgh`
- **Binary:** 87.7 KB (PolkaVM RISC-V)
- **Deployed:** 2026-07-11
- **Chain:** `rialo:devnet`
- **RPC:** `https://devnet.rialo.io:4101`
- **Deployer:** `8rpTEo1DqGvu5Y1Kxk9tycSDXF6wLUnWBiywnZHack4P`

## Production deployment

### Prerequisites

- Rialo developer access, RPC URL and CDK release (`@rialo/ts-cdk ^0.11.2`)
- Node.js >= 20

### Steps

```bash
# 1. Generate a dedicated devnet deployer key
npm run keygen
# Creates secrets/deployer.json — NEVER commit this file

# 2. Fund the deployer key with devnet RLO
# (Contact Rialo devnet faucet)

# 3. Deploy the v4 contract
RIALO_RPC_URL=https://devnet.rialo.io:4101 \
  RIALO_DEPLOYER_KEY_PATH=./secrets/deployer.json \
  npm run deploy:rialo

# 4. Save the returned program ID as RIALO_PROGRAM_ID in .env

# 5. Switch to RPC mode and test
RIALO_MODE=rpc npm test
RIALO_MODE=rpc npm run smoke
RIALO_MODE=rpc npm run cruise-smoke
```

### Environment variables

```
RIALO_MODE=mock|rpc
RIALO_RPC_URL=https://devnet.rialo.io:4101
RIALO_CHAIN_ID=rialo:devnet
RIALO_PROGRAM_ID=2RdznG7VJYGWaDyfZAWcuCBCbQ1cknMuZdDKfSVvTJgh  # AgentPermit v4
RIALO_DEPLOYER_KEY_PATH=./secrets/deployer.json
RIALO_RELAY_TOKEN=change-me-to-random-secret  # Rialo Cruise relay auth
```

## Security notes

- No private key is included in this repository
- No live-chain deployment is claimed
- Store deployer keys in a managed secret store (never in .env or committed)
- Replace HMAC receipt signing with KMS/HSM or REX-confidential signing for production
- Do not expose gateway API keys to agents
- Set `timelock_delay` to at least 3600 (1 hour) for production admin actions
- Configure at least 3 guardians for production multi-sig operations
- Set `RIALO_RELAY_TOKEN` to a long random string for Cruise relay auth
- Set `cruise_budget` to a reasonable limit to control gas sponsorship costs
