import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def audit_hash(event: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(event, sort_keys=True).encode("utf-8")).hexdigest()


def create_audit_event(
    *,
    workspace_id: str,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata: dict[str, Any] | None = None,
    previous_hash: str = "GENESIS",
    timestamp: str | None = None,
) -> dict[str, Any]:
    timestamp = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    body = {
        "workspaceId": workspace_id,
        "actorId": actor_id,
        "action": action,
        "resourceType": resource_type,
        "resourceId": resource_id,
        "metadata": metadata or {},
        "previousHash": previous_hash,
        "timestamp": timestamp,
    }
    return {**body, "hash": audit_hash(body)}


def verify_audit_chain(events: list[dict[str, Any]]) -> bool:
    previous = "GENESIS"
    for event in events:
        e = dict(event)
        h = e.pop("hash", "")
        if e.get("previousHash", "") != previous:
            return False
        if audit_hash(e) != h:
            return False
        previous = h
    return True
