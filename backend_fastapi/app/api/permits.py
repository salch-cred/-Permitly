from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext, get_rialo
from app.core.policy import make_id, now_iso
from app.core.receipts import sha256
from app.db import crud
from app.db.product_models import Permit
from app.core.rialo import RialoAdapter
import uuid
from datetime import datetime, timedelta, timezone

router = APIRouter(tags=["permits"])


@router.post("/api/permits")
async def create_permit(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    expires_in = body.get("expiresIn", 3600)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    permit = Permit(
        id=uuid.uuid4(),
        workspace_id=ws_id,
        agent_id=uuid.UUID(body["agentId"]),
        policy_id=uuid.UUID(body["policyId"]) if body.get("policyId") else None,
        scopes=[body.get("scope", "")],
        budget_cap=body.get("budgetCap", 0),
        max_per_action=body.get("maxPerAction"),
        rate_limit_per_minute=body.get("rateLimitPerMinute", 60),
        require_human_above=body.get("requireHumanAbove"),
        allowed_targets=body.get("allowedTargets", []),
        status="active",
        expires_at=expires_at,
    )
    await crud.add_item(db, permit)
    await rialo.record("issuePermit", {
        "permitId": str(permit.id),
        "agentId": body.get("agentId"),
        "policyId": body.get("policyId", ""),
        "scopeRoot": sha256(body.get("scope", "")),
        "budgetCap": body.get("budgetCap", 0),
        "maxPerAction": body.get("maxPerAction", 0),
        "expiresAt": int(expires_at.timestamp()),
    })
    return {"permit": {"id": str(permit.id), "agentId": str(permit.agent_id), "policyId": str(permit.policy_id) if permit.policy_id else None, "scope": body.get("scope", ""), "status": "active", "expiresAt": expires_at.isoformat(), "createdAt": permit.issued_at.isoformat()}}


@router.post("/api/permits/{permit_id}/freeze")
async def freeze_permit(
    permit_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    permit = await crud.get_item_by_id(db, Permit, uuid.UUID(permit_id))
    if not permit or permit.workspace_id != ws_id:
        raise HTTPException(status_code=404, detail="not_found")
    permit.status = "frozen"
    await crud.update_item(db, permit)
    await rialo.record("freezePermit", {"permitId": permit_id})
    return {"permit": {"id": str(permit.id), "status": "frozen"}}


@router.post("/api/permits/{permit_id}/unfreeze")
async def unfreeze_permit(
    permit_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    permit = await crud.get_item_by_id(db, Permit, uuid.UUID(permit_id))
    if not permit or permit.workspace_id != ws_id:
        raise HTTPException(status_code=404, detail="not_found")
    permit.status = "active"
    await crud.update_item(db, permit)
    await rialo.record("unfreezePermit", {"permitId": permit_id})
    return {"permit": {"id": str(permit.id), "status": "active"}}
