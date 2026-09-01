"""
mcp_trust.signing
------------------
Ed25519-based signing and verification of MCP tool/connector manifests.

A "manifest" here is the JSON-serializable declaration of a tool server's
identity and capability schema -- for mcp-api-connect, this is the
InvokeSpec / Connector definition (target, auth type [not secrets], and
request/response schema), NOT the credentials themselves.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 keypair. Returns (private_key_bytes, public_key_bytes)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def canonicalize(manifest: dict[str, Any]) -> bytes:
    """
    Deterministic byte serialization of a manifest for signing/hashing.
    Sorted keys, no whitespace ambiguity, UTF-8.

    Any field named exactly "signature" or "_meta" is excluded, since those
    describe the attestation itself rather than the attested content.
    """
    stripped = {k: v for k, v in manifest.items() if k not in ("signature", "_meta")}
    return json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class SignedManifest:
    manifest: dict[str, Any]
    signature_b64: str
    public_key_b64: str
    signed_at: float = field(default_factory=time.time)
    key_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = dict(self.manifest)
        out["signature"] = self.signature_b64
        out["_meta"] = {
            "public_key": self.public_key_b64,
            "signed_at": self.signed_at,
            "key_id": self.key_id,
        }
        return out


def sign_manifest(
    manifest: dict[str, Any], private_key_bytes: bytes, key_id: str = ""
) -> SignedManifest:
    """Sign a manifest dict, returning a SignedManifest wrapper."""
    priv = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = canonicalize(manifest)
    sig = priv.sign(payload)
    return SignedManifest(
        manifest=manifest,
        signature_b64=base64.b64encode(sig).decode("ascii"),
        public_key_b64=base64.b64encode(pub_bytes).decode("ascii"),
        key_id=key_id,
    )


@dataclass
class VerificationResult:
    valid: bool
    reason: str = ""


def verify_manifest(
    signed_dict: dict[str, Any], expected_public_key_b64: str | None = None
) -> VerificationResult:
    """
    Verify a signed manifest dict (as produced by SignedManifest.to_dict()).

    If expected_public_key_b64 is provided, the manifest's embedded public
    key must match it exactly (pinned-key model) -- this is what defends
    against a straightforward identity-spoofing attempt, since an attacker
    who doesn't hold the pinned private key cannot produce a valid signature
    the caller will accept, even if they embed their own public key.
    """
    if "signature" not in signed_dict or "_meta" not in signed_dict:
        return VerificationResult(False, "missing signature or metadata")

    meta = signed_dict["_meta"]
    embedded_pub_b64 = meta.get("public_key")
    if not embedded_pub_b64:
        return VerificationResult(False, "missing public key")

    if expected_public_key_b64 is not None and embedded_pub_b64 != expected_public_key_b64:
        return VerificationResult(False, "public key does not match pinned key (possible spoofing)")

    manifest = {k: v for k, v in signed_dict.items() if k not in ("signature", "_meta")}
    payload = canonicalize(manifest)

    try:
        pub_bytes = base64.b64decode(embedded_pub_b64)
        sig_bytes = base64.b64decode(signed_dict["signature"])
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, payload)
        return VerificationResult(True, "signature valid")
    except InvalidSignature:
        return VerificationResult(False, "invalid signature (tampered content or key)")
    except Exception as e:  # malformed base64, wrong key length, etc.
        return VerificationResult(False, f"malformed signature/key: {e}")
