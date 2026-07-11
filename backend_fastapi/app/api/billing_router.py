import os
import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext
from app.core.billing import PLANS, StripeBillingAdapter
from app.core.rbac import require_permission
from app.db import crud

router = APIRouter(prefix="/api/v1/billing", tags=["billing"])


@router.get("/plans")
async def list_plans():
    return {"plans": PLANS}


@router.post("/checkout")
async def create_checkout(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    try:
        require_permission(ctx.role, "billing:read")
    except PermissionError:
        raise HTTPException(status_code=403, detail="missing_permission")
    if ctx.user_id.startswith("api-key:"):
        raise HTTPException(status_code=403, detail="user_session_required")
    user = await crud.find_user_by_id(db, uuid.UUID(ctx.user_id))
    if not user:
        raise HTTPException(status_code=403, detail="user_not_found")
    billing = StripeBillingAdapter()
    try:
        checkout = await billing.create_checkout(
            customer_email=user.email,
            workspace_id=ctx.workspace_id,
            plan=body.get("plan", "team"),
            success_url=body.get("successUrl", ""),
            cancel_url=body.get("cancelUrl", ""),
        )
        return {"id": checkout.get("id"), "url": checkout.get("url")}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
