from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext, get_rialo
from app.core.policy import make_id, now_iso
from app.db import crud
from app.db.product_models import Agent
from app.core.rialo import RialoAdapter
import uuid

router = APIRouter(tags=["agents"])


@router.post("/api/agents")
async def create_agent(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    agent = Agent(
        id=uuid.uuid4(),
        workspace_id=ws_id,
        name=body.get("name", "Agent"),
        type=body.get("controller", "custom"),
        status="active",
        risk=0,
    )
    await crud.add_item(db, agent)
    await rialo.record("registerAgent", {
        "agentId": str(agent.id),
        "controller": body.get("controller", ""),
        "roleId": body.get("roleId", ""),
    })
    return {"agent": {"id": str(agent.id), "name": agent.name, "controller": agent.type, "active": True, "workspaceId": ctx.workspace_id, "createdAt": agent.created_at.isoformat()}}
