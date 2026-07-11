import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext
from app.core.rbac import require_permission
from app.core.security import random_token
from app.db import crud

router = APIRouter(prefix="/api/v1", tags=["team"])


@router.get("/team")
async def list_team(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    try:
        require_permission(ctx.role, "members:*")
    except PermissionError:
        raise HTTPException(status_code=403, detail="missing_permission")
    ws_id = uuid.UUID(ctx.workspace_id)
    members = await crud.list_members(db, ws_id)
    invitations = await crud.list_invitations(db, ws_id)
    invites_out = [{"id": str(i.id), "email": i.email, "role": i.role, "expiresAt": i.expires_at.isoformat()} for i in invitations]
    return {"members": members, "invitations": invites_out}


@router.post("/invitations")
async def create_invitation(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    try:
        require_permission(ctx.role, "members:*")
    except PermissionError:
        raise HTTPException(status_code=403, detail="missing_permission")
    if not body.get("email"):
        raise HTTPException(status_code=400, detail="email_required")
    token = random_token("inv")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    ws_id = uuid.UUID(ctx.workspace_id)
    await crud.create_invitation(
        db, workspace_id=ws_id, email=body["email"].lower(),
        role=body.get("role", "viewer"), token_hash=token_hash,
        expires_at=expires_at, invited_by=ctx.user_id,
    )
    await crud.append_audit(db, workspace_id=ws_id, actor_id=ctx.user_id,
                             action="invitation.created", resource_type="invitation",
                             resource_id=token_hash[:12],
                             metadata={"email": body["email"], "role": body.get("role", "viewer")})
    return {"token": token, "expiresAt": expires_at.isoformat(), "inviteUrl": f"/signup?invite={token}"}


@router.post("/invitations/{token}/accept")
async def accept_invitation(
    token: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    token_hash = hashlib.sha256(token.encode()).digest().hex()
    result = await crud.accept_invitation(db, token_hash, uuid.UUID(ctx.user_id))
    if not result:
        raise HTTPException(status_code=400, detail="invalid_expired_or_already_accepted")
    return {"message": "Joined workspace.", "workspaceId": result["workspace_id"], "role": result["role"]}
