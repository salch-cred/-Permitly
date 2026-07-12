from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext, get_rialo
from app.core.policy import make_id, now_iso
from app.db import crud
from app.db.product_models import Policy
from app.core.rialo import RialoAdapter
import uuid

router = APIRouter(tags=["policies"])


@router.post("/api/policies")
async def create_policy(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    policy_id = body.get("policyId", make_id("pol"))
    policy = Policy(
        id=uuid.UUID(policy_id) if "-" in policy_id else uuid.uuid4(),
        workspace_id=ws_id,
        name=body.get("name", ""),
        scopes=body.get("scopes", []),
        budget_cap=body.get("budgetCap", 0),
        max_per_action=body.get("maxPerAction", 0),
        rate_limit_per_minute=body.get("rateLimitPerMinute", 60),
        require_human_above=body.get("requireHumanAbove", 0),
        conditions=body.get("conditions", []),
        status="active",
        version=1,
    )
    await crud.add_item(db, policy)
    await rialo.record("publishPolicy", {
        "policyId": str(policy.id),
        "version": 1,
        "roleId": body.get("roleId"),
        "minApprovals": body.get("minApprovals", 0),
        "requiresTimelock": body.get("requiresTimelock", False),
    })
    return {"policy": {"id": str(policy.id), "name": policy.name, "scopes": policy.scopes, "status": policy.status, "version": policy.version, "createdAt": policy.created_at.isoformat()}}


@router.get("/api/policies")
async def list_policies(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    policies = await crud.list_workspace_items(db, Policy, ws_id)
    return {"items": [{"id": str(p.id), "name": p.name, "scopes": p.scopes, "budgetCap": p.budget_cap, "maxPerAction": p.max_per_action, "rateLimitPerMinute": p.rate_limit_per_minute, "conditions": p.conditions, "status": p.status, "version": p.version, "createdAt": p.created_at.isoformat()} for p in policies]}
