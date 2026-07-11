import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext
from app.core.rbac import require_permission
from app.core.security import month_period
from app.db import crud

router = APIRouter(prefix="/api/v1", tags=["usage"])


@router.get("/usage")
async def get_usage(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    period = month_period()
    usage = await crud.get_usage(db, workspace_id=ws_id, period=period)
    return {"usage": usage}


@router.post("/usage/decision")
async def increment_decision(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    try:
        require_permission(ctx.role, "permits:*")
    except PermissionError:
        raise HTTPException(status_code=403, detail="missing_permission")
    ws_id = uuid.UUID(ctx.workspace_id)
    period = month_period()
    value = await crud.increment_usage(db, workspace_id=ws_id, period=period, metric="decisions", amount=1)
    return {"value": value}
