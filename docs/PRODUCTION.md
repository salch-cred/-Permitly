# Production deployment and operations

## Included in v3

- Multi-tenant organization/workspace/user/membership schema
- Password authentication using scrypt and signed expiring sessions
- Workspace API keys stored as SHA-256 hashes and returned only once
- Role-based access control for owner, admin, policy author, approver, auditor and viewer
- SQLite development database plus PostgreSQL production migration
- Usage metering and plan enforcement primitives
- Stripe Checkout adapter and signature verification
- Signed outbound webhooks with retry metadata
- Durable database-backed job queue
- Hash-chained audit log verification
- TypeScript/JavaScript and Python SDKs
- OpenAPI 3.1 specification
- Docker Compose development/production database setup
- Existing permits, policy builder, approvals, credential vault, prompt firewall, emergency controls and Rialo adapter

## Production requirements supplied by the operator

1. Create cloud, PostgreSQL, DNS, email and Stripe accounts.
2. Put all secrets in a cloud secret manager—not in `.env` on a server.
3. Replace SQLite with the PostgreSQL repository before horizontal scaling.
4. Configure backups, point-in-time recovery and database connection pooling.
5. Obtain Rialo production RPC/CDK/REX access and deploy the reviewed program.
6. Run an independent penetration test and remediate findings.
7. Complete privacy, DPA, terms, incident-response and retention policies with qualified counsel.
8. Complete SOC 2 evidence collection before making compliance claims.

## Required secrets

- `SESSION_SECRET`
- `AGENTPERMIT_ADMIN_TOKEN`
- `RECEIPT_SIGNING_SECRET`
- `VAULT_MASTER_SECRET`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `POSTGRES_PASSWORD` or managed `DATABASE_URL`
- Rialo RPC and deployer configuration

Generate at least 32 random bytes for each cryptographic secret and use separate values.

## Deployment gates

- All automated tests pass
- Migrations apply to a clean database and a copy of staging data
- Restore test succeeds
- Stripe test-mode checkout and webhook succeed
- Webhook retry/dead-letter behavior succeeds
- Rialo testnet smoke test succeeds
- Load test meets the selected latency SLO
- Security review and dependency scanning pass
- Rollback procedure is exercised
