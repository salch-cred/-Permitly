import crypto from 'node:crypto';

const stable = value => JSON.stringify(value, Object.keys(value).sort());
export function auditHash(event) { return crypto.createHash('sha256').update(stable(event)).digest('hex'); }

export function createAuditEvent({ workspaceId, actorId, action, resourceType, resourceId, metadata = {}, previousHash = 'GENESIS', timestamp = new Date().toISOString() }) {
  const body = { workspaceId, actorId, action, resourceType, resourceId, metadata, previousHash, timestamp };
  return { ...body, hash: auditHash(body) };
}

export function verifyAuditChain(events) {
  let previous = 'GENESIS';
  for (const event of events) {
    const { hash, ...body } = event;
    if (body.previousHash !== previous || auditHash(body) !== hash) return false;
    previous = hash;
  }
  return true;
}
