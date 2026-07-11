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

### Key functions

**Admin:**
- `transfer_ownership`, `add_guardian`, `remove_guardian`, `set_timelock_delay`
- `schedule_timelock_action`, `execute_timelock_action`, `cancel_timelock_action`
- `emergency_stop`, `emergency_resume`

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

**Staking:**
- `deposit_stake`, `withdraw_stake`, `slash_stake`

**Credentials:**
- `register_credential_hash`

### Events

30+ events covering every state change: `AgentRegistered`, `DelegationCreated`, `RoleCreated`, `PolicyPublished`, `PermitIssued`, `PermitMigrated`, `PermitFrozen`, `ApprovalRequested`, `VoteCast`, `ApprovalDecided`, `StakeDeposited`, `StakeSlashed`, `TimelockScheduled`, `TimelockExecuted`, `PolicyMigrationStarted`, `PolicyMigrationCompleted`, and more.

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
```

### Environment variables

```
RIALO_MODE=mock|rpc
RIALO_RPC_URL=https://devnet.rialo.io:4101
RIALO_CHAIN_ID=rialo:devnet
RIALO_PROGRAM_ID=<from deploy step>
RIALO_DEPLOYER_KEY_PATH=./secrets/deployer.json
```

## Security notes

- No private key is included in this repository
- No live-chain deployment is claimed
- Store deployer keys in a managed secret store (never in .env or committed)
- Replace HMAC receipt signing with KMS/HSM or REX-confidential signing for production
- Do not expose gateway API keys to agents
- Set `timelock_delay` to at least 3600 (1 hour) for production admin actions
- Configure at least 3 guardians for production multi-sig operations
