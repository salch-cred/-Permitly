from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext
from app.core.rbac import require_permission
from app.db import crud
import uuid

router = APIRouter(prefix="/api/v1", tags=["webhooks"])


@router.post("/webhooks")
async def register_webhook(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    try:
        require_permission(ctx.role, "members:*")
    except PermissionError:
        raise HTTPException(status_code=403, detail="missing_permission")
    url = body.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="Webhook URL must use HTTPS")
    ws_id = uuid.UUID(ctx.workspace_id)
    wh = await crud.add_webhook(db, workspace_id=ws_id, url=url,
                                 secret=body.get("secret", ""),
                                 events=body.get("events", ["*"]))
    await crud.append_audit(db, workspace_id=ws_id, actor_id=ctx.user_id,
                             action="webhook.created", resource_type="webhook",
                             resource_id=str(wh.id),
                             metadata={"url": url, "events": body.get("events", ["*"])})
    return {"id": str(wh.id)}
