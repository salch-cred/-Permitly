from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext, get_rialo
from app.db import crud
from app.db.product_models import Approval
from app.core.rialo import RialoAdapter
from datetime import datetime, timezone
import uuid

router = APIRouter(tags=["approvals"])


@router.get("/api/approvals")
async def list_approvals(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    items = await crud.list_workspace_items(db, Approval, ws_id)
    return {"items": [{"id": str(a.id), "agentId": str(a.agent_id), "action": {"scope": a.action.get("scope", ""), "target": a.action.get("target", ""), "amount": a.action.get("amount", 0)} if isinstance(a.action, dict) else {"scope": str(a.action)}, "reason": a.reason, "status": a.status, "createdAt": a.created_at.isoformat()} for a in items]}


@router.post("/api/approvals/{approval_id}/vote")
async def cast_vote(
    approval_id: str,
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    approval = await crud.get_item_by_id(db, Approval, uuid.UUID(approval_id))
    if not approval:
        raise HTTPException(status_code=404, detail="not_found")
    if approval.status != "pending":
        raise HTTPException(status_code=400, detail="approval_closed")
    votes = approval.action.get("votes", [])
    votes.append({"guardian": body.get("guardian", ""), "approved": body.get("approved", False), "at": datetime.now(timezone.utc).isoformat()})
    approval.action = {**approval.action, "votes": votes}
    yes_votes = sum(1 for v in votes if v.get("approved"))
    no_votes = sum(1 for v in votes if not v.get("approved"))
    required = body.get("requiredVotes", 1)
    if yes_votes >= required:
        approval.status = "approved"
    elif no_votes >= required:
        approval.status = "denied"
    approval.decided_at = datetime.now(timezone.utc)
    await crud.update_item(db, approval)
    await rialo.record("castVote", {"approvalId": approval_id, "guardian": body.get("guardian", ""), "approved": body.get("approved", False)})
    return {"approval": {"id": str(approval.id), "status": approval.status, "votes": votes}}
