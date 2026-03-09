from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from django.conf import settings


def _derive_key() -> bytes:
    material = f"{settings.SECRET_KEY}|ports.provider.secret.v1".encode("utf-8")
    return hashlib.sha256(material).digest()


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    blocks: list[bytes] = []
    counter = 0
    while sum(len(b) for b in blocks) < length:
        counter_bytes = counter.to_bytes(4, "big")
        blocks.append(hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest())
        counter += 1
    return b"".join(blocks)[:length]


def encrypt_secret(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    key = _derive_key()
    nonce = secrets.token_bytes(16)
    pt = text.encode("utf-8")
    ks = _keystream(key, nonce, len(pt))
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return "v1:" + ".".join(
        [
            base64.urlsafe_b64encode(nonce).decode("ascii"),
            base64.urlsafe_b64encode(ct).decode("ascii"),
            base64.urlsafe_b64encode(tag).decode("ascii"),
        ]
    )


def decrypt_secret(token: str) -> str:
    raw = str(token or "").strip()
    if not raw:
        return ""
    if not raw.startswith("v1:"):
        # Backward compatibility: treat old/plain values as clear text.
        return raw
    key = _derive_key()
    payload = raw[3:]
    parts = payload.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid encrypted secret payload format")
    nonce = base64.urlsafe_b64decode(parts[0].encode("ascii"))
    ct = base64.urlsafe_b64decode(parts[1].encode("ascii"))
    tag = base64.urlsafe_b64decode(parts[2].encode("ascii"))
    expected = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Encrypted secret integrity check failed")
    ks = _keystream(key, nonce, len(ct))
    pt = bytes(a ^ b for a, b in zip(ct, ks))
    return pt.decode("utf-8")
