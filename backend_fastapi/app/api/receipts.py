import os
import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_auth_context, AuthContext
from app.core.receipts import verify_receipt
from app.db.product_models import Receipt
from app.db import crud

router = APIRouter(tags=["receipts"])


@router.get("/api/receipts")
async def list_receipts(
    ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    ws_id = uuid.UUID(ctx.workspace_id)
    items = await crud.list_workspace_items(db, Receipt, ws_id)
    return {"items": [{"id": str(r.id), "agentId": str(r.agent_id), "scope": r.scope, "amount": r.amount, "result": r.result, "hash": r.hash, "createdAt": r.created_at.isoformat()} for r in items]}


@router.get("/api/receipts/{receipt_id}/verify")
async def verify_receipt_endpoint(
    receipt_id: str,
    db: AsyncSession = Depends(get_db),
):
    receipt_item = await crud.get_item_by_id(db, Receipt, uuid.UUID(receipt_id))
    if not receipt_item:
        raise HTTPException(status_code=404, detail="not_found")
    receipt_dict = {
        "id": str(receipt_item.id),
        "workspaceId": str(receipt_item.workspace_id),
        "permitId": str(receipt_item.permit_id),
        "agentId": str(receipt_item.agent_id),
        "scope": receipt_item.scope,
        "target": receipt_item.target,
        "amount": receipt_item.amount,
        "result": receipt_item.result,
        "code": receipt_item.code,
        "reason": receipt_item.reason,
        "previousHash": receipt_item.previous_hash,
        "createdAt": receipt_item.created_at.isoformat(),
        "hash": receipt_item.hash,
        "signature": receipt_item.signature,
    }
    secret = os.environ.get("RECEIPT_SIGNING_SECRET", "dev-secret")
    valid = verify_receipt(receipt_dict, secret)
    return {"valid": valid, "receipt": receipt_dict}
