from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext, get_rialo
from app.core.policy import make_id, now_iso
from app.core.rialo import RialoAdapter
import json

router = APIRouter(tags=["stakes"])


@router.post("/api/stakes/deposit")
async def deposit_stake(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    stake = {
        "id": body.get("agentId", make_id("stk")),
        "agentId": body.get("agentId"),
        "amount": body.get("amount", 0),
        "status": "active",
        "workspaceId": ctx.workspace_id,
        "createdAt": now_iso(),
    }
    await rialo.record("depositStake", {"agentId": body.get("agentId"), "amount": body.get("amount", 0)})
    return {"stake": stake}
