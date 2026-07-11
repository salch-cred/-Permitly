import os
from fastapi import APIRouter, Depends, HTTPException
from app.api.deps import get_rialo
from app.core.rialo import RialoAdapter

router = APIRouter(tags=["cruise"])


@router.post("/api/cruise/relay")
async def cruise_relay(
    body: dict,
    rialo: RialoAdapter = Depends(get_rialo),
):
    relay_token = os.environ.get("RIALO_RELAY_TOKEN", "change-me-in-production")
    if body.get("relayToken") != relay_token:
        raise HTTPException(status_code=403, detail="invalid_relay_token")
    payload = body.get("payload")
    signature = body.get("signature")
    if not payload or not signature:
        raise HTTPException(status_code=400, detail="payload_and_signature_required")
    import time
    if payload.get("expiresAt") and int(time.time()) > payload["expiresAt"]:
        raise HTTPException(status_code=400, detail="meta_tx_expired")
    try:
        result = await rialo.record(payload.get("kind", "unknown"), {
            **(payload.get("params", {})),
            "signer": payload.get("signer"),
            "nonce": payload.get("nonce", 0),
            "gasAmount": payload.get("gasAmount", 1000),
        })
        return {"success": True, "txHash": result.get("txHash"), "block": result.get("block"), "status": result.get("status")}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"relay_failed: {e}")


@router.get("/api/cruise/nonce/{signer}")
async def cruise_nonce(
    signer: str,
    rialo: RialoAdapter = Depends(get_rialo),
):
    try:
        nonce = await rialo.get_nonce(signer)
        return {"signer": signer, "nonce": nonce}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"nonce_failed: {e}")


@router.post("/api/cruise/sponsored-permit")
async def cruise_sponsored_permit(
    body: dict,
    rialo: RialoAdapter = Depends(get_rialo),
):
    try:
        result = await rialo.record("sponsored_issue_permit", {
            "permitId": body.get("permitId", ""),
            "agentId": body.get("agentId"),
            "policyId": body.get("policyId"),
            "scopeRoot": body.get("scopeRoot", ""),
            "budgetCap": body.get("budgetCap", 0),
            "maxPerAction": body.get("maxPerAction", 0),
            "expiresAt": body.get("expiresAt"),
            "signer": body.get("signer"),
            "nonce": body.get("nonce", 0),
            "gasAmount": body.get("gasAmount", 1000),
        })
        return {"success": True, "txHash": result.get("txHash"), "permitId": body.get("permitId")}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"sponsored_permit_failed: {e}")


@router.get("/api/cruise/status")
async def cruise_status(
    rialo: RialoAdapter = Depends(get_rialo),
):
    health = await rialo.health()
    return {
        "cruiseEnabled": health.get("cruiseEnabled", False),
        "mode": health.get("mode"),
        "chainId": health.get("chainId"),
        "connected": health.get("connected"),
        "relayerConfigured": bool(os.environ.get("RIALO_RELAYER_KEY")),
    }
