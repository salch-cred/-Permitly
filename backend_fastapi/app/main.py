import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import get_settings
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
