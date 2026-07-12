import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.firewall import scan_for_prompt_injection
from app.db import crud
from app.db.product_models import Agent, Permit, Receipt, Approval, Credential, SecurityEvent, Incident
from app.api.deps import get_db, get_auth_context, AuthContext, get_rialo
from app.core.rialo import RialoAdapter
from app.api.auth import router as saas_router
from app.api.policies import router as policies_router
from app.api.agents import router as agents_router
from app.api.permits import router as permits_router
from app.api.credentials import router as credentials_router
from app.api.approvals import router as approvals_router
from app.api.actions import router as actions_router
from app.api.delegations import router as delegations_router
from app.api.stakes import router as stakes_router
from app.api.receipts import router as receipts_router
from app.api.cruise import router as cruise_router
from app.api.billing_router import router as billing_router
from app.api.team import router as team_router
from app.api.webhook_routes import router as webhook_router
from app.api.audit_routes import router as audit_router
from app.api.usage import router as usage_router
from app.api.roles import router as roles_router

settings = get_settings()

app = FastAPI(title="AgentPermit API", version="3.0.0")

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# Health
@app.get("/api/health")
async def health():
    from app.api.deps import get_rialo
    rialo = get_rialo()
    rialo_health = await rialo.health()
    return {"ok": True, "rialo": rialo_health}


# ── Dashboard convenience endpoints ──

@app.get("/api/summary")
async def dashboard_summary(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    agents = await crud.list_workspace_items(db, Agent, ws_id)
    permits = await crud.list_workspace_items(db, Permit, ws_id)
    approvals = await crud.list_workspace_items(db, Approval, ws_id)
    events = await crud.list_workspace_items(db, SecurityEvent, ws_id)
    incidents = await crud.list_workspace_items(db, Incident, ws_id)
    return {
        "activeAgents": sum(1 for a in agents if a.status == "active"),
        "pendingApprovals": sum(1 for a in approvals if a.status == "pending"),
        "securityEvents": len(events),
        "emergencyStopped": any(i.type == "emergency_stop" for i in incidents),
    }


@app.get("/api/securityEvents")
async def list_security_events(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    items = await crud.list_workspace_items(db, SecurityEvent, ws_id)
    return {"items": [{"id": str(e.id), "scan": e.scan, "source": e.source, "agentId": str(e.agent_id) if e.agent_id else None, "createdAt": e.created_at.isoformat()} for e in items]}


@app.get("/api/incidents")
async def list_incidents(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    items = await crud.list_workspace_items(db, Incident, ws_id)
    return {"items": [{"id": str(i.id), "type": i.type, "scope": i.scope, "agentId": str(i.agent_id) if i.agent_id else None, "reason": i.reason, "status": i.status, "createdAt": i.created_at.isoformat()} for i in items]}


@app.get("/api/security/rules")
async def list_security_rules(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    return {"items": [
        {"label": "Prompt injection patterns", "weight": 40},
        {"label": "PII / secrets in prompt", "weight": 30},
        {"label": "System prompt override", "weight": 25},
        {"label": "Chain-of-thought jailbreak", "weight": 35},
        {"label": "Role-play escape", "weight": 20},
        {"label": "Payload obfuscation", "weight": 30},
    ]}


@app.post("/api/security/scan")
async def security_scan(body: dict):
    content = body.get("content", "")
    scan = scan_for_prompt_injection(content)
    score = scan["score"]
    if score >= 70:
        level = "critical"
        recommendation = "Block immediately and review agent instruction."
    elif score >= 40:
        level = "high"
        recommendation = "Review before execution. Consider escalation."
    elif score >= 20:
        level = "medium"
        recommendation = "Monitor closely."
    else:
        level = "low"
        recommendation = "No action needed."
    return {"level": level, "score": score, "matches": scan["matches"], "recommendation": recommendation}


@app.post("/api/emergency-stop")
async def emergency_stop(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    reason = body.get("reason", "Emergency stop by operator")
    agent_id = body.get("agentId")
    # Revoke all active permits
    permits = await crud.list_workspace_items(db, Permit, ws_id)
    for p in permits:
        if p.status == "active":
            p.status = "revoked"
            p.revoked_at = datetime.now(timezone.utc)
            await crud.update_item(db, p)
    # Record incident
    incident = Incident(
        id=uuid.uuid4(), workspace_id=ws_id,
        type="emergency_stop", scope="workspace",
        agent_id=uuid.UUID(agent_id) if agent_id else None,
        reason=reason, status="active",
    )
    await crud.add_item(db, incident)
    await rialo.record("emergencyStop", {"reason": reason, "workspaceId": ctx.workspace_id})
    return {"stopped": True, "reason": reason, "incidentId": str(incident.id)}


@app.post("/api/emergency-resume")
async def emergency_resume(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    incident = Incident(
        id=uuid.uuid4(), workspace_id=ws_id,
        type="resume", scope="workspace",
        reason=body.get("reason", "Resumed by operator"),
        status="resolved",
    )
    await crud.add_item(db, incident)
    await rialo.record("emergencyResume", {"reason": body.get("reason", ""), "workspaceId": ctx.workspace_id})
    return {"resumed": True}


@app.post("/api/permits/{permit_id}/clone")
async def clone_permit(
    permit_id: str,
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    original = await crud.get_item_by_id(db, Permit, uuid.UUID(permit_id))
    if not original or original.workspace_id != ws_id:
        raise HTTPException(status_code=404, detail="not_found")
    from datetime import timedelta
    cloned = Permit(
        id=uuid.uuid4(), workspace_id=ws_id, agent_id=original.agent_id,
        scopes=original.scopes, budget_cap=original.budget_cap,
        max_per_action=original.max_per_action,
        rate_limit_per_minute=original.rate_limit_per_minute,
        require_human_above=original.require_human_above,
        allowed_targets=original.allowed_targets,
        status="active",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    await crud.add_item(db, cloned)
    await rialo.record("clonePermit", {"originalId": permit_id, "cloneId": str(cloned.id)})
    return {"permit": {"id": str(cloned.id), "agentId": str(cloned.agent_id), "status": "active"}}


@app.post("/api/agents/{agent_id}/revoke-permits")
async def revoke_agent_permits(
    agent_id: str,
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    permits = await crud.list_workspace_items(db, Permit, ws_id)
    revoked = 0
    for p in permits:
        if p.agent_id == uuid.UUID(agent_id) and p.status == "active":
            p.status = "revoked"
            p.revoked_at = datetime.now(timezone.utc)
            await crud.update_item(db, p)
            revoked += 1
    return {"revoked": revoked}


@app.post("/api/approvals/{approval_id}/approve")
async def approve_approval(
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
    approval.status = "approved"
    approval.reviewer = body.get("reviewer", ctx.user_id)
    approval.decided_at = datetime.now(timezone.utc)
    await crud.update_item(db, approval)
    await rialo.record("approveApproval", {"approvalId": approval_id})
    return {"approval": {"id": str(approval.id), "status": "approved"}}


@app.post("/api/approvals/{approval_id}/deny")
async def deny_approval(
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
    approval.status = "denied"
    approval.reviewer = body.get("reviewer", ctx.user_id)
    approval.decided_at = datetime.now(timezone.utc)
    await crud.update_item(db, approval)
    await rialo.record("denyApproval", {"approvalId": approval_id})
    return {"approval": {"id": str(approval.id), "status": "denied"}}


@app.delete("/api/credentials/{credential_id}")
async def delete_credential(
    credential_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    credential = await crud.get_item_by_id(db, Credential, uuid.UUID(credential_id))
    if not credential:
        raise HTTPException(status_code=404, detail="not_found")
    credential.status = "revoked"
    credential.revoked_at = datetime.now(timezone.utc)
    await crud.update_item(db, credential)
    return {"ok": True}


# Mount all API routers
app.include_router(saas_router)
app.include_router(policies_router)
app.include_router(agents_router)
app.include_router(permits_router)
app.include_router(credentials_router)
app.include_router(approvals_router)
app.include_router(actions_router)
app.include_router(delegations_router)
app.include_router(stakes_router)
app.include_router(receipts_router)
app.include_router(cruise_router)
app.include_router(billing_router)
app.include_router(team_router)
app.include_router(webhook_router)
app.include_router(audit_router)
app.include_router(usage_router)
app.include_router(roles_router)


# Static file serving (frontend)
_web_root = Path(__file__).resolve().parent.parent.parent / "apps" / "web"

_route_map = {
    "/": "landing.html",
    "/app": "index.html",
    "/signup": "signup.html",
    "/account": "account.html",
}


@app.api_route("/{path:path}", methods=["GET", "HEAD"])
async def serve_static(path: str):
    if path.startswith("api/"):
        raise HTTPException(status_code=404, detail="not_found")
    file_name = _route_map.get(f"/{path}")
    if not file_name:
        if path == "" or path == "/":
            file_name = "landing.html"
        else:
            file_name = path
    file_path = _web_root / file_name
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="not_found")
    ext = file_path.suffix
    media_type = {
        ".html": "text/html",
        ".css": "text/css",
        ".js": "text/javascript",
        ".svg": "image/svg+xml",
    }.get(ext, "application/octet-stream")
    return FileResponse(str(file_path), media_type=media_type)
