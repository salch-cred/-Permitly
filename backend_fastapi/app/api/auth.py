from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse, ApiKeyCreateRequest, ApiKeyCreateResponse
from app.core.config import get_settings
from app.core.security import password_hash, password_verify, create_api_key, sign_session, random_token
from app.core.rbac import require_permission
from app.db import crud
from app.api.deps import get_db, get_auth_context, AuthContext

router = APIRouter(prefix="/api/v1", tags=["saas"])


def make_session(user_id: str, workspace_id: str) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {"sub": user_id, "workspaceId": workspace_id, "iat": now, "exp": now + 86400}
    return sign_session(payload, get_settings().session_secret)


@router.post("/auth/register", response_model=RegisterResponse)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await crud.find_user_by_email(db, req.email)
    if existing:
        raise HTTPException(status_code=409, detail="email_already_registered")
    try:
        pw_hash = password_hash(req.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    org, ws, user = await crud.create_tenant(
        db,
        org_name=req.organizationName,
        org_slug=req.organizationSlug,
        workspace_name=req.workspaceName,
        workspace_slug=req.workspaceSlug,
        user_name=req.name,
        email=req.email,
        password_hash=pw_hash,
    )

    token = make_session(str(user.id), str(ws.id))
    await crud.append_audit(db, workspace_id=ws.id, actor_id=str(user.id),
                             action="tenant.created", resource_type="workspace",
                             resource_id=str(ws.id))
    return RegisterResponse(organizationId=str(org.id), workspaceId=str(ws.id), userId=str(user.id), token=token)


@router.post("/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await crud.find_user_by_email(db, req.email)
    if not user or not password_verify(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid_credentials")
    workspaces = await crud.workspaces_for_user(db, user.id)
    if not workspaces:
        raise HTTPException(status_code=403, detail="no_workspace")
    selected = workspaces[0]
    if req.workspaceId:
        for w in workspaces:
            if w["id"] == req.workspaceId:
                selected = w
                break
    token = make_session(str(user.id), selected["id"])
    return LoginResponse(token=token, user={"id": str(user.id), "email": user.email, "name": user.name}, workspace=selected)


@router.post("/auth/reset-request")
async def reset_request(body: dict, db: AsyncSession = Depends(get_db)):
    email = body.get("email", "")
    user = await crud.find_user_by_email(db, email)
    if not user:
        return {"message": "If that email exists, a reset link was sent."}
    token = random_token("reset", 32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    await crud.create_reset_token(db, user_id=user.id, token_hash=token_hash, expires_at=expires_at)
    return {"message": "Reset token generated.", "token": token, "expiresAt": expires_at.isoformat()}


@router.post("/auth/reset-confirm")
async def reset_confirm(body: dict, db: AsyncSession = Depends(get_db)):
    token = body.get("token")
    password = body.get("password")
    if not token or not password:
        raise HTTPException(status_code=400, detail="token_and_password_required")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        new_hash = password_hash(password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    ok = await crud.consume_reset_token(db, token_hash, new_hash)
    if not ok:
        raise HTTPException(status_code=400, detail="invalid_or_expired_token")
    return {"message": "Password updated successfully."}


@router.get("/me")
async def me(ctx: AuthContext = Depends(get_auth_context), db: AsyncSession = Depends(get_db)):
    user = None
    workspaces = []
    if not ctx.user_id.startswith("api-key:") and ctx.user_id != "admin":
        from sqlalchemy import select
        from app.db.models import User

        q = await db.execute(select(User).where(User.id == uuid.UUID(ctx.user_id)))
        row = q.scalar_one_or_none()
        if row:
            user = {"id": str(row.id), "email": row.email, "name": row.name}
            workspaces = await crud.workspaces_for_user(db, uuid.UUID(ctx.user_id))

    return {"user": user, "context": {"userId": ctx.user_id, "workspaceId": ctx.workspace_id, "role": ctx.role, "apiKeyId": ctx.api_key_id}, "workspaces": workspaces}


@router.post("/api-keys", response_model=ApiKeyCreateResponse)
async def create_key(req: ApiKeyCreateRequest, ctx: AuthContext = Depends(get_auth_context), db: AsyncSession = Depends(get_db)):
    try:
        require_permission(ctx.role, "members:*")
    except PermissionError:
        raise HTTPException(status_code=403, detail="missing_permission")
    if ctx.user_id.startswith("api-key:"):
        raise HTTPException(status_code=403, detail="user_session_required")
    environment = "live" if req.environment == "live" else "test"
    generated = create_api_key(environment)
    expires_at = None
    if req.expiresAt:
        try:
            expires_at = datetime.fromisoformat(req.expiresAt.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid_expiresAt")
    key = await crud.create_api_key(
        db,
        workspace_id=uuid.UUID(ctx.workspace_id),
        name=req.name,
        key_prefix=generated["key_prefix"],
        key_hash=generated["key_hash"],
        role=req.role,
        expires_at=expires_at,
    )
    await crud.append_audit(db, workspace_id=uuid.UUID(ctx.workspace_id), actor_id=ctx.user_id,
                             action="api_key.created", resource_type="api_key",
                             resource_id=str(key.id),
                             metadata={"prefix": key.key_prefix, "role": key.role})
    return {"key": {"id": str(key.id), "workspace_id": str(key.workspace_id), "name": key.name, "key_prefix": key.key_prefix, "role": key.role, "expires_at": key.expires_at, "created_at": key.created_at, "secret": generated["raw"]}}
