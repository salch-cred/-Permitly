import json
import os
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_rialo, RialoAdapter
from app.core.policy import evaluate_permit, make_id, now_iso
from app.core.receipts import create_receipt, sha256, verify_receipt
from app.core.firewall import scan_for_prompt_injection
from app.core.vault import decrypt_credential
from app.db import crud
from app.db.product_models import Permit, Agent, Policy, Approval, Receipt, SecurityEvent

router = APIRouter(tags=["actions"])


def _is_private_host(hostname: str) -> bool:
    if hostname in ("localhost", "0.0.0.0", "127.0.0.1", "::1"):
        return True
    import ipaddress
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


async def _execute_protected(request: dict, ws_id: str, db: AsyncSession) -> dict | None:
    if not request.get("execute"):
        return None
    target = request["execute"]
    url = target if isinstance(target, str) else target.get("url", "")
    parsed = httpx.URL(url)
    if parsed.scheme != "https" or _is_private_host(parsed.host):
        raise HTTPException(status_code=400, detail="Protected execution requires a public HTTPS target")
    headers = {"content-type": "application/json", **(request.get("headers", {}))}
    if request.get("credentialId"):
        cred = await crud.get_item_by_id(db, uuid.UUID(request["credentialId"]))
        if not cred or cred.status != "active":
            raise HTTPException(status_code=400, detail="Credential is unavailable")
        vault_secret = os.environ.get("VAULT_MASTER_SECRET", os.environ.get("RECEIPT_SIGNING_SECRET", "dev-secret"))
        credential = decrypt_credential(cred.encrypted, vault_secret)
        if credential:
            if credential.get("type") == "bearer":
                headers["authorization"] = f"Bearer {credential['token']}"
            else:
                import base64
                token = base64.b64encode(f"{credential['username']}:{credential['password']}".encode()).decode()
                headers["authorization"] = f"Basic {token}"
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json=request.get("body", {}))
        return {"status": response.status_code, "body": response.text}


@router.post("/api/actions/authorize")
async def authorize_action(
    body: dict,
    db: AsyncSession = Depends(get_db),
    rialo: RialoAdapter = Depends(get_rialo),
):
    permit_id = body.get("permitId")
    permit_uuid = uuid.UUID(permit_id) if permit_id else None
    if not permit_uuid:
        raise HTTPException(status_code=400, detail="permitId_required")

    permit_item = await crud.get_item_by_id(db, Permit, permit_uuid)
    if not permit_item:
        raise HTTPException(status_code=404, detail="permit_not_found")

    ws_id = str(permit_item.workspace_id)
    request = {
        "agentId": body.get("agentId", str(permit_item.agent_id)),
        "scope": body.get("scope", permit_item.scopes[0] if permit_item.scopes else ""),
        "target": body.get("target"),
        "amount": body.get("amount", 0),
    }

    scan = scan_for_prompt_injection(body.get("input", ""))
    if scan["score"] >= 70:
        receipt = create_receipt(request=request, permit={"id": permit_id, "workspaceId": ws_id},
                                  evaluation={"decision": "blocked", "code": "firewall", "reason": "Prompt injection detected"},
                                  secret=os.environ.get("RECEIPT_SIGNING_SECRET", "dev-secret"))
        await rialo.record("recordDenial", {"permitId": permit_id, "actionHash": sha256(body.get("input", "")), "receiptId": receipt["id"], "previousHash": "", "result": 4})
        return {"evaluation": {"decision": "blocked", "reason": "Prompt injection detected"}, "scan": scan, "receipt": receipt}

    permit_dict = {
        "id": str(permit_item.id),
        "workspace_id": ws_id,
        "agentId": str(permit_item.agent_id),
        "scopes": permit_item.scopes,
        "budgetCap": permit_item.budget_cap,
        "maxPerAction": permit_item.max_per_action,
        "rateLimitPerMinute": permit_item.rate_limit_per_minute,
        "requireHumanAbove": permit_item.require_human_above,
        "allowedTargets": permit_item.allowed_targets,
        "conditions": permit_item.conditions,
        "status": permit_item.status,
        "expiresAt": permit_item.expires_at.isoformat(),
        "spent": getattr(permit_item, "spent", 0) or body.get("_spent", 0),
    }

    evaluation = evaluate_permit(permit=permit_dict, request=request)
    if evaluation["decision"] == "authorized":
        amount = float(body.get("amount", 0))
        exec_result = await _execute_protected(body, ws_id, db) if body.get("execute") else None
        receipt = create_receipt(
            request=request,
            permit={"id": permit_id, "workspaceId": ws_id},
            evaluation=evaluation,
            execution=exec_result,
            secret=os.environ.get("RECEIPT_SIGNING_SECRET", "dev-secret"),
        )
        await rialo.record("authorizeAndConsume", {
            "permitId": permit_id, "actionHash": sha256(json.dumps(body, sort_keys=True)),
            "amount": amount, "receiptId": receipt["id"], "previousHash": "",
        })
        return {"evaluation": evaluation, "receipt": receipt, "scan": scan, "execution": exec_result}

    if evaluation["decision"] == "escalated":
        approval_id = body.get("approvalId", make_id("apr"))
        approval = Approval(
            id=uuid.uuid4(),
            workspace_id=permit_item.workspace_id,
            permit_id=permit_item.id,
            agent_id=permit_item.agent_id,
            action=body,
            status="pending",
            reason=evaluation.get("reason", ""),
        )
        await crud.add_item(db, approval)
        await rialo.record("requestApproval", {
            "approvalId": str(approval.id), "permitId": permit_id,
            "actionHash": sha256(json.dumps(body, sort_keys=True)),
            "amount": amount, "requiredVotes": 1,
        })
        return {"evaluation": evaluation, "approval": {"id": str(approval.id), "status": "pending"}, "scan": scan}

    receipt = create_receipt(
        request=request,
        permit={"id": permit_id, "workspaceId": ws_id},
        evaluation=evaluation,
        secret=os.environ.get("RECEIPT_SIGNING_SECRET", "dev-secret"),
    )
    result_code = {"denied_budget": 2, "denied_scope": 3}.get(evaluation.get("code", ""), 4)
    await rialo.record("recordDenial", {
        "permitId": permit_id, "actionHash": sha256(json.dumps(body, sort_keys=True)),
        "receiptId": receipt["id"], "previousHash": "", "result": result_code,
    })
    return {"evaluation": evaluation, "receipt": receipt, "scan": scan}
