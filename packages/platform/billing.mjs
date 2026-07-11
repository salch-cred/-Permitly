import crypto from 'node:crypto';

export const PLANS = {
  developer: { monthly: 0, agents: 3, decisions: 1000, retentionDays: 7 },
  team: { monthly: 19900, agents: 20, decisions: 50000, retentionDays: 90 },
  business: { monthly: 79900, agents: Infinity, decisions: 500000, retentionDays: 365 },
  enterprise: { monthly: null, agents: Infinity, decisions: Infinity, retentionDays: 2555 }
};

export function enforcePlan(planName, usage, resource) {
  const plan = PLANS[planName] || PLANS.developer;
  const limit = resource === 'agents' ? plan.agents : plan.decisions;
  const current = Number(usage?.[resource] || 0);
  return { allowed: current < limit, current, limit, remaining: limit === Infinity ? Infinity : Math.max(0, limit-current) };
}

export class StripeBillingAdapter {
  constructor({ secretKey = process.env.STRIPE_SECRET_KEY, webhookSecret = process.env.STRIPE_WEBHOOK_SECRET, priceMap = {} } = {}) { this.secretKey=secretKey; this.webhookSecret=webhookSecret; this.priceMap=priceMap; }
  async createCheckout({ customerEmail, workspaceId, plan, successUrl, cancelUrl }) {
    if (!this.secretKey) throw new Error('STRIPE_SECRET_KEY is required');
    const price=this.priceMap[plan]||process.env[`STRIPE_PRICE_${plan.toUpperCase()}`]; if(!price)throw new Error(`Stripe price missing for ${plan}`);
    const form=new URLSearchParams({'mode':'subscription','customer_email':customerEmail,'line_items[0][price]':price,'line_items[0][quantity]':'1','success_url':successUrl,'cancel_url':cancelUrl,'metadata[workspace_id]':workspaceId,'metadata[plan]':plan});
    const endpoint = 'https:' + '//api.stripe.com/v1/checkout/sessions';
    const r=await fetch(endpoint,{method:'POST',headers:{authorization:`Bearer ${this.secretKey}`,'content-type':'application/x-www-form-urlencoded'},body:form}); const j=await r.json(); if(!r.ok)throw new Error(j.error?.message||'Stripe error'); return j;
  }
  verifyEvent(rawBody, signatureHeader) {
    if(!this.webhookSecret)throw new Error('STRIPE_WEBHOOK_SECRET is required');
    const parts=Object.fromEntries(String(signatureHeader).split(',').map(x=>x.split('=')));const timestamp=parts.t;const sig=parts.v1;const expected=crypto.createHmac('sha256',this.webhookSecret).update(`${timestamp}.${rawBody}`).digest('hex');
    if(!sig||expected.length!==sig.length||!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(sig)))throw new Error('Invalid Stripe signature');
    return JSON.parse(rawBody);
  }
}
