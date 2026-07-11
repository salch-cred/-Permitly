from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import sha256_hex, verify_session
from app.db.session import make_engine, make_session_factory
from app.db import crud

_engine = None
_SessionLocal = None


def _get_session_factory():
    global _engine, _SessionLocal
    if _SessionLocal is None:
        settings = get_settings()
        _engine = make_engine(settings.database_url)
        _SessionLocal = make_session_factory(_engine)
    return _SessionLocal


async def get_db() -> AsyncSession:
    SessionLocal = _get_session_factory()
    async with SessionLocal() as session:
        yield session


class AuthContext:
    def __init__(self, *, user_id: str, workspace_id: str, role: str, api_key_id: str | None = None):
        self.user_id = user_id
        self.workspace_id = workspace_id
        self.role = role
        self.api_key_id = api_key_id


async def get_auth_context(
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> AuthContext:
    if not authorization:
        raise HTTPException(status_code=401, detail="authentication_required")
    token = authorization.replace("Bearer ", "")

    if token.startswith("ap_"):
        key = await crud.auth_api_key(db, sha256_hex(token))
        if not key:
            raise HTTPException(status_code=401, detail="invalid_api_key")
        return AuthContext(user_id=f"api-key:{key.id}", workspace_id=str(key.workspace_id), role=key.role, api_key_id=str(key.id))

    payload = verify_session(token, get_settings().session_secret)
    if not payload:
        raise HTTPException(status_code=401, detail="invalid_session")

    user_id = uuid.UUID(payload["sub"])
    workspace_id = uuid.UUID(payload["workspaceId"])
    membership = await crud.membership_for_user(db, user_id, workspace_id)
    if not membership:
        raise HTTPException(status_code=403, detail="no_membership")

    return AuthContext(user_id=str(user_id), workspace_id=str(workspace_id), role=membership.role)
