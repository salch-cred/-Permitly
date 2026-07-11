from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext, get_rialo
from app.core.policy import make_id, now_iso
from app.core.receipts import sha256
from app.core.rialo import RialoAdapter
import json
import uuid

router = APIRouter(tags=["delegations"])


@router.post("/api/delegations")
async def create_delegation(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    expires_in = body.get("expiresIn", 3600)
    delegation = {
        "id": body.get("delegationId", make_id("dlg")),
        "agentId": body.get("agentId"),
        "delegate": body.get("delegate"),
        "scope": body.get("scope", ""),
        "expiresAt": int(__import__("time").time()) + expires_in,
        "active": True,
        "workspaceId": ctx.workspace_id,
        "createdAt": now_iso(),
    }
    await db.execute(
        __import__("sqlalchemy").text("SELECT 1")  # no-op, delegation stored in file-based store
    )
    await rialo.record("createDelegation", {
        "delegationId": delegation["id"],
        "agentId": body.get("agentId"),
        "delegate": body.get("delegate"),
        "scopeRoot": sha256(body.get("scope", "")),
        "expiresAt": delegation["expiresAt"],
    })
    return {"delegation": delegation}
