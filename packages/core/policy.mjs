import crypto from 'node:crypto';

export function id(prefix = 'id') {
  return `${prefix}_${crypto.randomUUID().replaceAll('-', '').slice(0, 20)}`;
}

export function nowIso(clock = Date) { return new clock().toISOString(); }

function normalizeScope(s = '') { return String(s).trim().toLowerCase(); }

export function scopeAllows(granted, requested) {
  const g = normalizeScope(granted);
  const r = normalizeScope(requested);
  if (g === '*' || g === r) return true;
  if (g.endsWith(':*')) return r.startsWith(g.slice(0, -1));
  return false;
}

export function evaluatePermit({ permit, request, receipts = [], now = new Date() }) {
  if (!permit) return deny('permit_not_found', 'No permit was supplied');
  if (permit.status !== 'active') return deny(`permit_${permit.status}`, `Permit is ${permit.status}`);
  if (new Date(permit.expiresAt).getTime() <= now.getTime()) return deny('permit_expired', 'Permit has expired');
  if (permit.agentId !== request.agentId) return deny('agent_mismatch', 'Permit belongs to another agent');

  const allowed = (permit.scopes || []).some(s => scopeAllows(s, request.scope));
  if (!allowed) return deny('scope_denied', `Scope ${request.scope} is not granted`);

  const amount = Number(request.amount || 0);
  if (!Number.isFinite(amount) || amount < 0) return deny('invalid_amount', 'Amount must be a non-negative number');
  if (permit.maxPerAction != null && amount > Number(permit.maxPerAction)) {
    return escalate('per_action_limit', `Amount exceeds per-action limit of ${permit.maxPerAction}`);
  }

  const spent = receipts.filter(r => r.permitId === permit.id && r.result === 'authorized')
    .reduce((sum, r) => sum + Number(r.amount || 0), 0);
  if (spent + amount > Number(permit.budgetCap || 0)) {
    return escalate('budget_exceeded', `Action would exceed budget cap of ${permit.budgetCap}`);
  }

  if (permit.allowedTargets?.length && request.target && !permit.allowedTargets.includes(request.target)) {
    return deny('target_denied', 'Target is not on the permit allowlist');
  }

  if (permit.requireHumanAbove != null && amount > Number(permit.requireHumanAbove)) {
    return escalate('human_threshold', `Amount requires human approval above ${permit.requireHumanAbove}`);
  }

  const windowMs = 60_000;
  const recent = receipts.filter(r => r.permitId === permit.id && (now.getTime() - new Date(r.createdAt).getTime()) < windowMs);
  if (permit.rateLimitPerMinute && recent.length >= permit.rateLimitPerMinute) {
    return deny('rate_limited', 'Permit rate limit reached');
  }

  return { decision: 'authorized', code: 'ok', reason: 'Permit conditions satisfied', spent, remaining: Number(permit.budgetCap || 0) - spent - amount };
}

function deny(code, reason) { return { decision: 'blocked', code, reason }; }
function escalate(code, reason) { return { decision: 'escalated', code, reason }; }
