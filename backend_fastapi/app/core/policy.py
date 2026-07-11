from __future__ import annotations
import uuid
import re
from datetime import datetime, timezone
from typing import Any


def make_id(prefix: str = "id") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_scope(s: str = "") -> str:
    return str(s).strip().lower()


def scope_allows(granted: str, requested: str) -> bool:
    g = _normalize_scope(granted)
    r = _normalize_scope(requested)
    if g == "*" or g == r:
        return True
    if g.endswith(":*"):
        return r.startswith(g[:-1])
    return False


def evaluate_permit(
    *,
    permit: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    request = request or {}
    if not permit:
        return {"decision": "blocked", "code": "permit_not_found", "reason": "No permit was supplied"}
    status = permit.get("status", "")
    if status != "active":
        return {"decision": "blocked", "code": f"permit_{status}", "reason": f"Permit is {status}"}
    expires_at = permit.get("expiresAt") or permit.get("expires_at")
    if expires_at:
        if isinstance(expires_at, str):
            expires_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).replace(tzinfo=None)
        else:
            expires_dt = datetime.fromtimestamp(expires_at, tz=timezone.utc).replace(tzinfo=None)
        if expires_dt <= now.replace(tzinfo=None):
            return {"decision": "blocked", "code": "permit_expired", "reason": "Permit has expired"}
    agent_id = permit.get("agentId") or permit.get("agent_id")
    req_agent_id = request.get("agentId") or request.get("agent_id")
    if agent_id and req_agent_id and agent_id != req_agent_id:
        return {"decision": "blocked", "code": "agent_mismatch", "reason": "Permit belongs to another agent"}
    scopes = permit.get("scopes", []) or permit.get("scopes", [])
    req_scope = request.get("scope", "")
    allowed = any(scope_allows(s, req_scope) for s in scopes)
    if not allowed:
        return {"decision": "blocked", "code": "scope_denied", "reason": f"Scope {req_scope} is not granted"}
    amount = float(request.get("amount", 0))
    if amount < 0:
        return {"decision": "blocked", "code": "invalid_amount", "reason": "Amount must be non-negative"}
    max_per_action = permit.get("maxPerAction") or permit.get("max_per_action")
    if max_per_action is not None and amount > float(max_per_action):
        return {"decision": "escalated", "code": "per_action_limit", "reason": f"Amount exceeds per-action limit of {max_per_action}"}
    require_human_above = permit.get("requireHumanAbove") or permit.get("require_human_above")
    if require_human_above is not None and amount > float(require_human_above):
        return {"decision": "escalated", "code": "human_threshold", "reason": f"Amount requires human approval above {require_human_above}"}
    allowed_targets = permit.get("allowedTargets", []) or permit.get("allowed_targets", [])
    req_target = request.get("target")
    if allowed_targets and req_target and req_target not in allowed_targets:
        return {"decision": "blocked", "code": "target_denied", "reason": "Target is not on the permit allowlist"}
    conditions = permit.get("conditions", []) or permit.get("conditions", [])
    for cond in conditions:
        field_value = request.get(cond["field"]) or (request.get("context") or {}).get(cond["field"])
        if field_value is None:
            continue
        passes = False
        op = cond.get("operator", "")
        val = cond.get("value")
        if op == "eq":
            passes = str(field_value) == str(val)
        elif op == "neq":
            passes = str(field_value) != str(val)
        elif op == "lte":
            passes = float(field_value) <= float(val)
        elif op == "lt":
            passes = float(field_value) < float(val)
        elif op == "gte":
            passes = float(field_value) >= float(val)
        elif op == "gt":
            passes = float(field_value) > float(val)
        elif op == "in":
            passes = field_value in val if isinstance(val, list) else field_value == val
        elif op == "not_in":
            passes = field_value not in val if isinstance(val, list) else field_value != val
        elif op == "between":
            lo, hi = val
            passes = float(lo) <= float(field_value) <= float(hi)
        else:
            passes = True
        if not passes:
            return {"decision": "blocked", "code": "condition_failed", "reason": f"Condition not met: {cond['field']} {op} {val}"}
    allowed_hours = permit.get("allowedHoursUtc") or permit.get("allowed_hours_utc")
    if isinstance(allowed_hours, list) and len(allowed_hours) == 2:
        start_h, end_h = allowed_hours
        h = now.hour
        if not (start_h <= h < end_h):
            return {"decision": "blocked", "code": "time_restricted", "reason": f"Action only allowed {start_h}:00–{end_h}:00 UTC"}
    budget_cap = float(permit.get("budgetCap", 0) or permit.get("budget_cap", 0))
    spent = float(permit.get("spent", 0) or 0)
    if spent + amount > budget_cap:
        return {"decision": "escalated", "code": "budget_exceeded", "reason": f"Action would exceed budget cap of {budget_cap}"}
    return {
        "decision": "authorized",
        "code": "ok",
        "reason": "Permit conditions satisfied",
        "spent": int(spent),
        "remaining": int(budget_cap - spent - amount),
    }
