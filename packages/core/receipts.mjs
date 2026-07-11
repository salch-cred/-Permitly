import crypto from 'node:crypto';
import { id, nowIso } from './policy.mjs';

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}

export function sha256(value) { return crypto.createHash('sha256').update(typeof value === 'string' ? value : stable(value)).digest('hex'); }
export function sign(value, secret) { return crypto.createHmac('sha256', secret).update(stable(value)).digest('hex'); }
export function verify(value, signature, secret) {
  const expected = sign(value, secret);
  return signature?.length === expected.length && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

export function createReceipt({ request, permit, evaluation, execution, previousHash = 'GENESIS', secret, clock = Date }) {
  const body = {
    id: id('rcpt'),
    workspaceId: permit.workspaceId,
    permitId: permit.id,
    agentId: request.agentId,
    scope: request.scope,
    target: request.target || null,
    amount: Number(request.amount || 0),
    result: evaluation.decision,
    code: evaluation.code,
    reason: evaluation.reason,
    execution: execution ? { status: execution.status, digest: sha256(execution.body || '') } : null,
    previousHash,
    createdAt: nowIso(clock)
  };
  const hash = sha256(body);
  return { ...body, hash, signature: sign({ hash, workspaceId: body.workspaceId }, secret) };
}

export function verifyReceipt(receipt, secret) {
  const { hash, signature, ...body } = receipt;
  return hash === sha256(body) && verify({ hash, workspaceId: body.workspaceId }, signature, secret);
}
