import hashlib
import hmac
import json
import os
from typing import Any

import httpx

PLANS: dict[str, dict[str, Any]] = {
    "developer": {"monthly": 0, "agents": 3, "decisions": 1000, "retentionDays": 7},
    "team": {"monthly": 19900, "agents": 20, "decisions": 50000, "retentionDays": 90},
    "business": {"monthly": 79900, "agents": float("inf"), "decisions": 500000, "retentionDays": 365},
    "enterprise": {"monthly": None, "agents": float("inf"), "decisions": float("inf"), "retentionDays": 2555},
}


def enforce_plan(plan_name: str, usage: dict[str, int] | None, resource: str) -> dict[str, Any]:
    plan = PLANS.get(plan_name, PLANS["developer"])
    limit = plan.get("agents" if resource == "agents" else "decisions", float("inf"))
    current = usage.get(resource, 0) if usage else 0
    remaining = float("inf") if limit == float("inf") else max(0, limit - current)
    return {"allowed": current < limit, "current": current, "limit": limit, "remaining": remaining}


class StripeBillingAdapter:
    def __init__(self):
        self.secret_key = os.environ.get("STRIPE_SECRET_KEY")
        self.webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")

    async def create_checkout(
        self, *, customer_email: str, workspace_id: str, plan: str, success_url: str, cancel_url: str
    ) -> dict[str, Any]:
        if not self.secret_key:
            raise ValueError("STRIPE_SECRET_KEY is required")
        price = os.environ.get(f"STRIPE_PRICE_{plan.upper()}")
        if not price:
            raise ValueError(f"Stripe price missing for {plan}")
        form = httpx.QueryParams({
            "mode": "subscription",
            "customer_email": customer_email,
            "line_items[0][price]": price,
            "line_items[0][quantity]": "1",
            "success_url": success_url,
            "cancel_url": cancel_url,
            "metadata[workspace_id]": workspace_id,
            "metadata[plan]": plan,
        })
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://api.stripe.com/v1/checkout/sessions",
                headers={"Authorization": f"Bearer {self.secret_key}", "Content-Type": "application/x-www-form-urlencoded"},
                content=str(form),
            )
            j = r.json()
            if not r.is_success:
                err = j.get("error", {}).get("message", "Stripe error")
                raise ValueError(err)
            return j

    def verify_event(self, raw_body: bytes, signature_header: str) -> dict[str, Any]:
        if not self.webhook_secret:
            raise ValueError("STRIPE_WEBHOOK_SECRET is required")
        parts = dict(p.split("=") for p in signature_header.split(","))
        timestamp = parts.get("t", "")
        sig = parts.get("v1", "")
        expected = hmac.new(
            self.webhook_secret.encode("utf-8"),
            f"{timestamp}.{raw_body.decode('utf-8')}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not sig or len(expected) != len(sig) or not hmac.compare_digest(expected, sig):
            raise ValueError("Invalid Stripe signature")
        return json.loads(raw_body)
