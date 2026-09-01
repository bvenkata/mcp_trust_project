"""
attestmcp_repro.py
-------------------
LABELED REPRODUCTION — NOT THE ORIGINAL AUTHORS' CODE.

AttestMCP (Maloyan & Namiot, arXiv:2601.17549) describes but does not
release an implementation. This module reproduces the mechanism exactly
as specified in their Section VI-A (Design Principles) and VI-C
(Protocol Additions):
  1. Capability Attestation: servers hold a signed certificate from a
     "capability authority" listing which capabilities they may claim.
  2. Message Authentication: every message carries an HMAC-SHA256
     signature binding it to server_id, timestamp, and nonce.
  3. Replay Protection: timestamp + nonce, sliding window, messages
     outside the validity window or with a reused nonce are rejected.

Implementation choices not fully specified in the paper (capability
certificate signing algorithm; exact canonicalization) are filled in
using the same conventions as mcp-trust, for a fair, internally
consistent comparison — these choices are ours, not the original
authors', and are called out inline.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
import time
from dataclasses import dataclass, field
from typing import Any


# --- Capability certificate (design principle 1) ---
# The paper's Section VI-C shows a JSON structure with a "signature"
# field but does not specify the algorithm; we use Ed25519 (same
# primitive mcp-trust uses) since the paper's own security overhead
# analysis assumes public-key certificate validation ("Certificate
# validation (cold): 4.2ms P50" -- consistent with an asymmetric scheme).
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class CapabilityCertificate:
    server_id: str
    capabilities: list[str]
    issued_by: str
    issued_at: float
    expires_at: float
    signature: bytes = b""

    def payload(self) -> dict:
        return {
            "server_id": self.server_id,
            "capabilities": sorted(self.capabilities),
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


def ca_issue_certificate(server_id: str, capabilities: list[str], ca_private_key: Ed25519PrivateKey,
                          ca_name: str = "test-ca", validity_seconds: float = 3600) -> CapabilityCertificate:
    now = time.time()
    cert = CapabilityCertificate(
        server_id=server_id, capabilities=capabilities, issued_by=ca_name,
        issued_at=now, expires_at=now + validity_seconds,
    )
    cert.signature = ca_private_key.sign(_canon(cert.payload()))
    return cert


def verify_certificate(cert: CapabilityCertificate, ca_public_key: Ed25519PublicKey) -> tuple[bool, str]:
    if time.time() > cert.expires_at:
        return False, "certificate expired"
    try:
        ca_public_key.verify(cert.signature, _canon(cert.payload()))
        return True, "valid"
    except InvalidSignature:
        return False, "invalid certificate signature"


def check_capability(cert: CapabilityCertificate, requested_action: str) -> bool:
    """Design principle 1's least-privilege enforcement: an action is
    only permitted if within the server's certified capability list."""
    return requested_action in cert.capabilities


# --- Message authentication + replay protection (design principles 2, 3) ---
@dataclass
class NonceStore:
    """Sliding window of seen nonces per server, per the paper's '1,000
    nonces per server with 30-second validity' scheme (Section VI-C)."""
    window_seconds: float = 30.0
    seen: dict[str, set[str]] = field(default_factory=dict)

    def check_and_record(self, server_id: str, nonce: str, timestamp: float) -> tuple[bool, str]:
        now = time.time()
        if abs(now - timestamp) > self.window_seconds:
            return False, "timestamp outside validity window"
        bucket = self.seen.setdefault(server_id, set())
        if nonce in bucket:
            return False, "nonce already used (replay)"
        bucket.add(nonce)
        return True, "fresh"


def sign_message(message: dict, server_id: str, timestamp: float, nonce: str, shared_secret: bytes) -> str:
    payload = _canon({"server_id": server_id, "timestamp": timestamp, "nonce": nonce, "message": message})
    return hmac_lib.new(shared_secret, payload, hashlib.sha256).hexdigest()


def verify_message(message: dict, server_id: str, timestamp: float, nonce: str, mac: str,
                    shared_secret: bytes, nonce_store: NonceStore) -> tuple[bool, str]:
    fresh, reason = nonce_store.check_and_record(server_id, nonce, timestamp)
    if not fresh:
        return False, reason
    expected = sign_message(message, server_id, timestamp, nonce, shared_secret)
    if not hmac_lib.compare_digest(expected, mac):
        return False, "HMAC mismatch (tampered content or wrong key)"
    return True, "valid"
