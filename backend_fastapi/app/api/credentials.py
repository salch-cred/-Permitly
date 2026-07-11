import os
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext, get_rialo
from app.core.policy import make_id
from app.core.vault import encrypt_credential, redact_credential
from app.core.receipts import sha256
from app.db import crud
from app.db.product_models import Credential
from app.core.rialo import RialoAdapter
import uuid

router = APIRouter(tags=["credentials"])


@router.post("/api/credentials")
async def create_credential(
    body: dict,
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    vault_secret = os.environ.get("VAULT_MASTER_SECRET", os.environ.get("RECEIPT_SIGNING_SECRET", "dev-secret"))
    encrypted = encrypt_credential(body.get("value", {}), vault_secret)
    credential = Credential(
        id=uuid.uuid4(),
        workspace_id=ws_id,
        name=body.get("name", "Credential"),
        provider=body.get("provider", "custom"),
        encrypted=encrypted,
    )
    await crud.add_item(db, credential)
    await rialo.record("registerCredentialHash", {
        "credentialId": str(credential.id),
        "metadataHash": sha256({"name": body.get("name", ""), "provider": body.get("provider", "")}),
    })
    return {"credential": {"id": str(credential.id), "name": credential.name, "provider": credential.provider, "configured": True}}
