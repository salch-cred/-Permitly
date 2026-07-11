# Permitly — AI Agent Permissions & Proof (SaaS)

Permitly is a multi-tenant control plane for autonomous AI agents.

It authenticates organizations and workloads, evaluates scoped policies **before** tool execution, routes high‑risk actions to humans, protects service credentials, records signed receipts, and anchors governance events through a Rialo adapter.

## What’s included in this repo

- Marketing landing + product UI (landing, signup/login, account console, dashboard)
- SaaS foundation: orgs/workspaces/users/memberships + RBAC roles
- Password auth, expiring sessions, hashed workspace API keys
- Tenant-isolated product objects: agents, policies, permits, receipts, approvals, credentials, incidents
- Visual policy builder, budgets, expiry, rate limits, emergency stop
- Prompt-injection firewall + AES‑256‑GCM credential vault
- Usage metering + plan limits + Stripe adapter skeleton
- Signed webhooks + durable queue skeleton + hash‑chained audit log
- Dev SQLite schema + Postgres migration SQL (for Neon)
- JS + Python SDKs + OpenAPI spec
- Rialo adapter + mock ledger + contract reference
- Docker + automated tests + smoke tests

## Run locally

```bash
cp .env.example .env
npm test
npm run dev
```

Open:

- Marketing: `http://127.0.0.1:8787/`
- Signup/login: `http://127.0.0.1:8787/signup`
- Account console: `http://127.0.0.1:8787/account`
- Product dashboard: `http://127.0.0.1:8787/app`

## Validation

```bash
npm test
npm run smoke
npm run smoke:saas
```

---

# What’s NEXT to complete (production checklist)

Below is the exact remaining work to ship Permitly as a real SaaS with:
- **Frontend on Vercel**
- **Backend on Hugging Face (Docker Space)**
- **Database on Neon Postgres**

## 1) Decide backend runtime (important)

You currently have:
- **Node backend (apps/api)** powering the UI now
- A partial **FastAPI backend scaffold (backend_fastapi/)** started for the “entire backend on Hugging Face” plan

Choose one:

- **Option A (fastest to launch):** deploy the existing Node API to Hugging Face Docker Space.
- **Option B (your request):** finish the FastAPI backend and deploy that to Hugging Face.

> Recommended for speed: Option A now, migrate to Option B later.

## 2) Neon Postgres (required)

1. Create a Neon project + database.
2. Copy connection string and set as `DATABASE_URL`.
3. Run migrations:
   - If using Node backend: apply SQL from `database/postgres/001_init.sql` (or add a migration runner).
   - If using FastAPI backend: generate Alembic migration and run `alembic upgrade head`.

## 3) Hugging Face backend deployment (required)

### Create a Docker Space
- New Space → **Docker**
- Set the Space to run the backend service.

### Add Secrets (HF Space → Settings → Secrets)
Minimum:
- `DATABASE_URL` (Neon)
- `SESSION_SECRET` (long random)
- `RECEIPT_SIGNING_SECRET` (long random)
- `VAULT_MASTER_SECRET` (long random)
- `CORS_ORIGINS` (your Vercel domain)

If using Stripe now:
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`

## 4) Vercel frontend deployment (required)

1. Deploy the frontend.
2. Configure the frontend to call your backend base URL (HF Space URL).
3. Confirm CORS is correct.

## 5) Blob storage (choose one)

Pick one for attachments/exports:
- **Vercel Blob** (simple if you’re already on Vercel)
- **Cloudflare R2 / S3** (more portable)

Then implement:
- upload endpoint in backend
- signed URL generation
- file metadata stored in Postgres

## 6) Stripe billing (if you want paid plans)

1. Create products + price IDs (Team / Business).
2. Add price IDs as env vars.
3. Implement webhook handlers:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`

## 7) Background jobs / retries (needed for reliability)

Hugging Face is not ideal for cron.
Use one:
- **GitHub Actions cron** → calls `POST /api/internal/jobs/run`
- **Upstash QStash** (recommended)

Use this for:
- webhook retry
- queue processing
- cleanup tasks

## 8) Rialo production integration (later)

1. Decide Rialo mode (mock vs RPC).
2. Configure:
   - RPC URL, chain id, program id
   - production keys/permissions
3. Verify receipts anchored and independently verifiable.

## 9) Security + Ops (must before selling)

- Rate limiting (edge or reverse proxy)
- Monitoring + alerting (errors + latency)
- Backups (Neon)
- Legal pages: Terms, Privacy, DPA (if B2B)
- Threat model + external security review

---

# Quick “Next actions” (do these in order)

1. Create **Neon** DB → get `DATABASE_URL`
2. Create **HF Docker Space** → set secrets
3. Deploy backend to HF (Node now or FastAPI when complete)
4. Deploy frontend to **Vercel** → set backend URL
5. Test: signup → create API key → create permit → authorize action → receipt created

