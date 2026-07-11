import crypto from 'node:crypto';

export function signWebhook(payload, secret, timestamp = Math.floor(Date.now()/1000)) {
  const raw = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', secret).update(`${timestamp}.${raw}`).digest('hex');
  return { timestamp, signature, header: `t=${timestamp},v1=${signature}` };
}

export function verifyWebhook(payload, header, secret, toleranceSeconds = 300) {
  const parts = Object.fromEntries(String(header).split(',').map(x => x.split('=')));
  const timestamp = Number(parts.t); const signature = parts.v1;
  if (!timestamp || !signature || Math.abs(Date.now()/1000 - timestamp) > toleranceSeconds) return false;
  const expected = signWebhook(payload, secret, timestamp).signature;
  return expected.length === signature.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

export async function deliverWebhook({ url, event, secret, attempt = 1, fetchImpl = fetch }) {
  const body = JSON.stringify(event); const signed = signWebhook(body, secret);
  const response = await fetchImpl(url, { method:'POST', headers:{'content-type':'application/json','x-agentpermit-signature':signed.header,'x-agentpermit-event':event.type,'x-agentpermit-delivery':event.id}, body });
  return { ok: response.ok, status: response.status, attempt, nextRetryAt: response.ok ? null : new Date(Date.now()+Math.min(3600_000,1000*2**attempt)).toISOString() };
}
