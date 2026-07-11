from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext
from app.core.policy import make_id

router = APIRouter(tags=["roles"])


@router.post("/api/roles")
async def create_role(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    role = {
        "id": body.get("roleId", make_id("role")),
        "name": body.get("name", ""),
        "scopes": body.get("scopes", []),
        "maxBudget": body.get("maxBudget", 0),
        "maxPerAction": body.get("maxPerAction", 0),
        "canDelegate": body.get("canDelegate", False),
        "canApprove": body.get("canApprove", False),
        "workspaceId": ctx.workspace_id,
    }
    return {"role": role}
