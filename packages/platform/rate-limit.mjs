export class SlidingWindowRateLimiter {
  constructor({ windowMs = 60_000, max = 100 } = {}) { this.windowMs = windowMs; this.max = max; this.buckets = new Map(); }
  consume(key, now = Date.now()) {
    const values = (this.buckets.get(key) || []).filter(t => now - t < this.windowMs);
    if (values.length >= this.max) return { allowed: false, remaining: 0, retryAfterMs: this.windowMs - (now - values[0]) };
    values.push(now); this.buckets.set(key, values);
    return { allowed: true, remaining: this.max - values.length, retryAfterMs: 0 };
  }
  clear(key) { this.buckets.delete(key); }
}
