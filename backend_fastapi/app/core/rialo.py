import json
import os
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.receipts import sha256


class RialoAdapter:
    def __init__(self, data_dir: str | None = None):
        self.mode = os.environ.get("RIALO_MODE", "mock")
        self.rpc_url = os.environ.get("RIALO_RPC_URL", "https://devnet.rialo.io:4101")
        self.chain_id = os.environ.get("RIALO_CHAIN_ID", "rialo:devnet")
        self.program_id = os.environ.get("RIALO_PROGRAM_ID", "local-agentpermit")
        self.data_dir = data_dir or os.environ.get("DATA_DIR", "./data")
        self.relayer_key = os.environ.get("RIALO_RELAYER_KEY", None)

    async def record(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        envelope = {
            "chainId": self.chain_id,
            "programId": self.program_id,
            "kind": kind,
            "payload": payload,
            "nonce": int(datetime.now(timezone.utc).timestamp() * 1000),
            "version": 4,
        }
        if self.mode == "rpc":
            try:
                async with httpx.AsyncClient() as client:
                    result = await client.post(
                        f"{self.rpc_url}/call",
                        json={"programId": self.program_id, "method": kind, "args": envelope},
                        timeout=30,
                    )
                    data = result.json()
                    return {
                        "txHash": data.get("signature", sha256(envelope)),
                        "block": data.get("slot", 0),
                        "status": "finalized",
                        **envelope,
                    }
            except Exception as e:
                print(f"[RialoAdapter] RPC call failed ({e}), using mock fallback")
        return await self._mock_record(envelope)

    async def _mock_record(self, envelope: dict[str, Any]) -> dict[str, Any]:
        os.makedirs(self.data_dir, exist_ok=True)
        ledger_path = os.path.join(self.data_dir, "ledger.json")
        ledger = []
        try:
            with open(ledger_path, "r") as f:
                ledger = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        tx = {"txHash": sha256(envelope), "block": len(ledger) + 1, "status": "finalized", **envelope}
        ledger.append(tx)
        with open(ledger_path, "w") as f:
            json.dump(ledger, f, indent=2)
        return tx

    async def read(self, key: str) -> list[dict[str, Any]]:
        if self.mode == "rpc":
            try:
                async with httpx.AsyncClient() as client:
                    result = await client.post(
                        f"{self.rpc_url}/lineage",
                        json={"programId": self.program_id, "key": key},
                        timeout=30,
                    )
                    return result.json() or []
            except Exception:
                pass
        ledger_path = os.path.join(self.data_dir, "ledger.json")
        try:
            with open(ledger_path, "r") as f:
                ledger = json.load(f)
            return [x for x in ledger if x.get("payload", {}).get("id") == key
                    or x.get("payload", {}).get("permitId") == key
                    or x.get("payload", {}).get("agentId") == key
                    or x.get("payload", {}).get("approvalId") == key
                    or x.get("payload", {}).get("delegationId") == key]
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    async def read_by_kind(self, kind: str) -> list[dict[str, Any]]:
        ledger_path = os.path.join(self.data_dir, "ledger.json")
        try:
            with open(ledger_path, "r") as f:
                ledger = json.load(f)
            return [x for x in ledger if x.get("kind") == kind]
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    async def health(self) -> dict[str, Any]:
        if self.mode == "rpc":
            try:
                async with httpx.AsyncClient() as client:
                    health = await client.get(f"{self.rpc_url}/health", timeout=10)
                    block = await client.post(f"{self.rpc_url}/blockHeight", timeout=10)
                    return {
                        "mode": "rpc",
                        "chainId": self.chain_id,
                        "rpcUrl": self.rpc_url,
                        "connected": health.json().get("status") == "ok",
                        "blockHeight": block.json().get("height", 0),
                        "contractVersion": 4,
                        "cruiseEnabled": bool(self.relayer_key),
                    }
            except Exception as e:
                return {
                    "mode": "rpc",
                    "chainId": self.chain_id,
                    "rpcUrl": self.rpc_url,
                    "connected": False,
                    "error": str(e),
                    "contractVersion": 4,
                    "cruiseEnabled": False,
                }
        return {
            "mode": "mock",
            "chainId": self.chain_id,
            "programId": self.program_id,
            "connected": True,
            "contractVersion": 4,
            "cruiseEnabled": True,
        }

    async def get_nonce(self, signer_address: str) -> int:
        if self.mode == "rpc":
            try:
                async with httpx.AsyncClient() as client:
                    result = await client.post(
                        f"{self.rpc_url}/call",
                        json={"programId": self.program_id, "method": "getMetaTxNonce", "signer": signer_address},
                        timeout=30,
                    )
                    return int(result.json().get("result", 0))
            except Exception:
                pass
        ledger_path = os.path.join(self.data_dir, "ledger.json")
        try:
            with open(ledger_path, "r") as f:
                ledger = json.load(f)
            meta_txs = [x for x in ledger if x.get("kind") in (
                "sponsored_issue_permit", "sponsored_authorize", "sponsored_record_denial"
            )]
            return len(meta_txs)
        except (FileNotFoundError, json.JSONDecodeError):
            return 0

    def create_meta_tx_payload(self, kind: str, params: dict, signer: str, nonce: int, gas_amount: int = 1000) -> dict:
        return {
            "kind": kind,
            "params": params,
            "signer": signer,
            "nonce": nonce,
            "gasAmount": gas_amount,
            "chainId": self.chain_id,
            "programId": self.program_id,
            "expiresAt": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "version": 1,
        }
