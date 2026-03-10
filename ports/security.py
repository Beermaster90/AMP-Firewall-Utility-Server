from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
import socket
from urllib.parse import urlparse

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


def _split_csv_setting(name: str) -> list[str]:
    raw = str(getattr(settings, name, "") or "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def validate_management_url(url: str, *, setting_name: str) -> str:
    value = str(url or "").strip()
    if not value:
        raise ValueError("URL is required.")

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are allowed.")
    if not parsed.hostname:
        raise ValueError("URL hostname is required.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be embedded in the URL.")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError("URL must not include params, query string, or fragment.")

    allowed_hosts = {host.lower() for host in _split_csv_setting(setting_name)}
    hostname = parsed.hostname.lower()
    if allowed_hosts and hostname not in allowed_hosts:
        raise ValueError(f"Host '{parsed.hostname}' is not in {setting_name}.")

    try:
        addrinfos = socket.getaddrinfo(parsed.hostname, parsed.port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Hostname resolution failed: {exc}") from exc

    for info in addrinfos:
        ip_text = info[4][0]
        ip = ipaddress.ip_address(ip_text)
        if not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
        ):
            raise ValueError(
                f"Resolved address {ip_text} is public. Only private, loopback, or link-local targets are allowed."
            )

    return value


def validate_firewall_protocol(protocol: str) -> str:
    value = str(protocol or "").strip().lower()
    if value not in {"tcp", "udp", "0", "1", "6", "17"}:
        raise ValueError("Protocol must be TCP or UDP.")
    if value in {"0", "6"}:
        return "tcp"
    if value in {"1", "17"}:
        return "udp"
    return value


def validate_provider_section_name(section: str) -> str:
    value = str(section or "").strip()
    if not value:
        raise ValueError("Section is required.")
    if not value.replace("_", "").replace("-", "").isalnum():
        raise ValueError("Section contains invalid characters.")
    return value
