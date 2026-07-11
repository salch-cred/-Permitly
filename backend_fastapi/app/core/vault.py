import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _derive_key(secret: str) -> bytes:
    import hashlib
    return hashlib.scrypt(secret.encode("utf-8"), salt=b"agentpermit-vault-v1", n=2**14, r=8, p=1, dklen=32)


def encrypt_credential(value: dict[str, Any], master_secret: str) -> dict[str, Any]:
    key = _derive_key(master_secret)
    aes = AESGCM(key)
    iv = os.urandom(12)
    data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ct = aes.encrypt(iv, data, None)
    return {
        "version": 1,
        "algorithm": "aes-256-gcm",
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }


def decrypt_credential(record: dict[str, Any], master_secret: str) -> dict[str, Any]:
    if record.get("version") != 1:
        raise ValueError("Unsupported credential record")
    key = _derive_key(master_secret)
    aes = AESGCM(key)
    iv = base64.b64decode(record["iv"])
    ct = base64.b64decode(record["ciphertext"])
    pt = aes.decrypt(iv, ct, None)
    return json.loads(pt.decode("utf-8"))


def redact_credential(item: dict[str, Any]) -> dict[str, Any]:
    safe = {k: v for k, v in item.items() if k != "encrypted"}
    safe["configured"] = bool(item.get("encrypted"))
    return safe
