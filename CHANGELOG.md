# Changelog

## 4.1.0

- **Rialo Cruise ⛽**: Gas-less meta-transactions — users don't need RIALO tokens
- **Sponsored permit issuance**: Permits issued with relayer paying gas fees
- **Sponsored authorization**: Actions authorized with relayer paying gas
- **Sponsored denial recording**: Denials recorded with relayer paying gas
- **Meta-transaction relay**: Off-chain signed payloads submitted by Permitly backend
- **Nonce-based replay protection**: Per-signer monotonically increasing nonces
- **Cruise budget management**: Configurable gas sponsorship budget with spending tracking
- **New contract state**: meta_tx_nonces, meta_tx_relayer, sponsored_permits, cruise_budget, cruise_spent
- **New events**: MetaTxRelayed, CruiseBudgetSet, CruiseBudgetSpent, RelayerSet, SponsoredPermitIssued
- **New API endpoints**: /api/cruise/status, /api/cruise/nonce/:signer, /api/cruise/sponsored-permit, /api/cruise/relay
- **New adapter methods**: createMetaTxPayload, signMetaTxPayload, verifyMetaTxSignature, relayMetaTx, getNonce
- **Cruise smoke tests**: Full test suite for gas-less transaction flow
- **Updated docs**: Complete Rialo Cruise documentation with architecture diagram and SDK usage

## 4.0.0

- **Multi-sig Guardians**: N-of-M guardian approval system for high-risk actions
- **Delegation**: Scoped, time-bound delegate authorizations for agents
- **Role-based Policies**: Roles define scope roots, budgets, delegation/approval permissions
- **Staking & Slashing**: Agents stake tokens; violations trigger slashing with audit trail
- **Timelock**: Configurable delay on admin actions before execution
- **Policy Migration**: Live migration of permits between policy versions
- **Freeze/Unfreeze**: Emergency freeze of individual permits without global stop
- **Expanded Rialo contract**: 30+ events, 40+ functions, 15 state maps
- **Updated Rialo adapter**: v4 convenience methods, readByKind, contract version tracking
- **Updated deploy script**: v4 metadata, feature tagging, improved output
- **Comprehensive smoke tests**: Covers all v4 features including multi-sig voting

## 3.0.0

- Added signup, login and workspace account console
- Added multi-tenant organizations, workspaces, memberships and RBAC
- Added tenant-isolated product data and workspace API key authentication
- Added SQLite development schema and PostgreSQL production migration
- Added usage metering, SaaS plans and Stripe Checkout adapter
- Added signed webhooks, durable jobs and hash-chained audit logs
- Added JavaScript and Python SDKs plus OpenAPI 3.1
- Added Docker Compose and production operations documentation

## 2.0.0

- Added visual policy builder and policy publishing API
- Added human approval inbox with approve/deny decisions
- Added workspace and agent emergency kill switches
- Added AES-256-GCM credential vault with secret redaction
- Added prompt-injection firewall and security event feed
- Added SSRF protection for protected HTTP execution
- Added incident timeline, security center and expanded risk controls
- Expanded Rialo program with policy hashes, approvals, credential metadata and emergency state
- Expanded smoke tests and security unit tests

## 1.0.0

- Initial permits, policy evaluation, receipts, Rialo adapter and dashboard
