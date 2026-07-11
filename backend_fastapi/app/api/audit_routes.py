import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext
from app.core.audit import verify_audit_chain
from app.core.rbac import require_permission
from app.db import crud

router = APIRouter(prefix="/api/v1", tags=["audit"])


@router.get("/audit")
async def list_audit(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    try:
        require_permission(ctx.role, "audit:read")
    except PermissionError:
        raise HTTPException(status_code=403, detail="missing_permission")
    ws_id = uuid.UUID(ctx.workspace_id)
    events = await crud.audit_events(db, ws_id)
    event_dicts = []
    for e in events:
        event_dicts.append({
            "id": e.id,
            "workspaceId": str(e.workspace_id),
            "actorId": e.actor_id,
            "action": e.action,
            "resourceType": e.resource_type,
            "resourceId": e.resource_id,
            "metadata": e.audit_metadata,
            "previousHash": e.previous_hash,
            "hash": e.hash,
            "timestamp": e.timestamp.isoformat(),
        })
    chain_valid = verify_audit_chain(event_dicts)
    return {"items": event_dicts, "chainValid": chain_valid}
