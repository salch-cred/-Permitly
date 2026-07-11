import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def random_token(prefix: str, nbytes: int = 32) -> str:
    return f"{prefix}_{secrets.token_urlsafe(nbytes)}"


def create_api_key(environment: str = "live") -> dict[str, str]:
    prefix = "ap_live" if environment == "live" else "ap_test"
    raw = random_token(prefix)
    key_prefix = raw[:16]
    key_hash = sha256_hex(raw)
    return {"raw": raw, "key_prefix": key_prefix, "key_hash": key_hash}


def sign_session(payload: dict[str, Any], secret: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"AP_SESSION"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json_dumps(payload).encode()).rstrip(b"=").decode()
    msg = f"{header}.{body}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{header}.{body}.{signature}"


def verify_session(token: str, secret: str) -> dict[str, Any] | None:
    try:
        header, body, signature = token.split(".")
        msg = f"{header}.{body}".encode()
        expected = base64.urlsafe_b64encode(hmac.new(secret.encode(), msg, hashlib.sha256).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(expected, signature):
            return None
        payload = json_loads(base64.urlsafe_b64decode(body + "==").decode())
        exp = int(payload.get("exp", 0))
        if exp <= int(datetime.now(timezone.utc).timestamp()):
            return None
        return payload
    except Exception:
        return None


def password_hash(password: str, salt: str | None = None) -> str:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    salt = salt or secrets.token_hex(16)
    key = hashlib.scrypt(password.encode(), salt=salt.encode(), n=2**14, r=8, p=1, dklen=64)
    return f"scrypt${salt}${key.hex()}"


def password_verify(password: str, encoded: str) -> bool:
    try:
        scheme, salt, expected = encoded.split("$")
        if scheme != "scrypt":
            return False
        computed = password_hash(password, salt)
        return hmac.compare_digest(computed, encoded)
    except Exception:
        return False


def encrypt_credential(value: dict[str, Any], master_secret: str) -> dict[str, Any]:
    key = hashlib.scrypt(master_secret.encode(), salt=b"agentpermit-vault-v1", n=2**14, r=8, p=1, dklen=32)
    aes = AESGCM(key)
    iv = os.urandom(12)
    data = json_dumps(value).encode()
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
    key = hashlib.scrypt(master_secret.encode(), salt=b"agentpermit-vault-v1", n=2**14, r=8, p=1, dklen=32)
    aes = AESGCM(key)
    iv = base64.b64decode(record["iv"])
    ct = base64.b64decode(record["ciphertext"])
    pt = aes.decrypt(iv, ct, None)
    return json_loads(pt.decode())


def json_dumps(value: Any) -> str:
    import json

    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def json_loads(value: str) -> Any:
    import json

    return json.loads(value)


def month_period(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m")
