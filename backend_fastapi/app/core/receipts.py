import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from app.core.policy import make_id, now_iso


def _stable(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ",".join(_stable(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items())
        return "{" + ",".join(f"{json.dumps(k)}:{_stable(v)}" for k, v in items) + "}"
    return json.dumps(value, sort_keys=True)


def sha256(value: Any) -> str:
    if not isinstance(value, str):
        value = _stable(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sign(value: Any, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), _stable(value).encode("utf-8"), hashlib.sha256).hexdigest()


def verify(value: Any, signature: str, secret: str) -> bool:
    expected = sign(value, secret)
    return len(signature) == len(expected) and hmac.compare_digest(expected, signature)


def create_receipt(
    *,
    request: dict[str, Any],
    permit: dict[str, Any],
    evaluation: dict[str, Any],
    execution: dict[str, Any] | None = None,
    previous_hash: str = "GENESIS",
    secret: str,
) -> dict[str, Any]:
    body = {
        "id": make_id("rcpt"),
        "workspaceId": permit.get("workspaceId") or permit.get("workspace_id"),
        "permitId": permit.get("id"),
        "agentId": request.get("agentId") or request.get("agent_id"),
        "scope": request.get("scope", ""),
        "target": request.get("target"),
        "amount": float(request.get("amount", 0)),
        "result": evaluation.get("decision", "unknown"),
        "code": evaluation.get("code", ""),
        "reason": evaluation.get("reason", ""),
        "execution": {"status": execution.get("status"), "digest": sha256(execution.get("body", "") or "")} if execution else None,
        "previousHash": previous_hash,
        "createdAt": now_iso(),
    }
    h = sha256(body)
    body["hash"] = h
    body["signature"] = sign({"hash": h, "workspaceId": body["workspaceId"]}, secret)
    return body


def verify_receipt(receipt: dict[str, Any], secret: str) -> bool:
    r = dict(receipt)
    h = r.pop("hash", "")
    sig = r.pop("signature", "")
    body_hash = sha256(r)
    return body_hash == h and verify({"hash": body_hash, "workspaceId": r.get("workspaceId", "")}, sig, secret)
