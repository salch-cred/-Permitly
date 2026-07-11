from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.api.auth import router as saas_router

settings = get_settings()

app = FastAPI(title="AgentPermit API", version="3.0.0")

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"] ,
        allow_headers=["*"] ,
    )

app.include_router(saas_router)


@app.get("/health")
async def health():
    return {"ok": True, "service": "agentpermit-fastapi"}
