import crypto from 'node:crypto';

const b64 = value => Buffer.from(value).toString('base64url');
const unb64 = value => Buffer.from(value, 'base64url').toString('utf8');

export async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  if (String(password).length < 12) throw new Error('Password must contain at least 12 characters');
  const hash = await new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (e, key) => e ? reject(e) : resolve(key)));
  return `scrypt$${salt}$${hash.toString('hex')}`;
}

export async function verifyPassword(password, encoded) {
  const [scheme, salt, expected] = String(encoded).split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(encoded));
}

export function createSession(payload, secret, ttlSeconds = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64(JSON.stringify({ alg: 'HS256', typ: 'AP_SESSION' }));
  const body = b64(JSON.stringify({ ...payload, iat: now, exp: now + ttlSeconds, jti: crypto.randomUUID() }));
  const signature = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

export function verifySession(token, secret) {
  try {
    const [header, body, signature] = String(token).split('.');
    if (!header || !body || !signature) return null;
    const expected = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    if (expected.length !== signature.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) return null;
    const payload = JSON.parse(unb64(body));
    if (payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

export function createApiKey(prefix = 'ap_live') {
  const secret = crypto.randomBytes(32).toString('base64url');
  const raw = `${prefix}_${secret}`;
  return { raw, prefix: raw.slice(0, 16), hash: crypto.createHash('sha256').update(raw).digest('hex') };
}

export function hashApiKey(raw) { return crypto.createHash('sha256').update(String(raw)).digest('hex'); }
