"""
mcp_trust.trust_layer
----------------------
Bind-time verification layer combining signing, drift detection, and
audit logging into a single check, applied at the point where an agent
or orchestrator binds to a tool/connector -- i.e., before invocation,
not embedded inside the tool server itself. This mirrors the enterprise
pattern of centralizing trust decisions at the integration boundary
rather than inside each individual partner integration.

`spec_to_manifest` adapts an mcp-api-connect InvokeSpec (as documented in
its README: target, auth [type only, never credentials], request_format,
response_format) into the signable manifest shape used here.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from .signing import sign_manifest, verify_manifest, SignedManifest
from .drift import check_drift, DriftResult
from .audit_log import HashChainAuditLog


def spec_to_manifest(invoke_spec: dict[str, Any]) -> dict[str, Any]:
    """
    Reduce a full InvokeSpec (which may contain an auth `config` dict with
    live credential material, e.g. api_key values) down to the identity/
    capability surface that should be attested: protocol, auth *type*
    (not secrets), and request/response shape. Credentials are never
    signed or logged.
    """
    target = invoke_spec.get("target", {})
    auth = invoke_spec.get("auth", {})
    return {
        "target": {
            "base_url": target.get("base_url"),
            "protocol": target.get("protocol", "rest"),
        },
        "auth": {
            "type": auth.get("type", "none"),
            # auth.config intentionally omitted -- credentials are not part
            # of the attested identity/capability surface
        },
        "request_format": copy.deepcopy(invoke_spec.get("request_format", {})),
        "response_format": copy.deepcopy(invoke_spec.get("response_format", {})),
    }


@dataclass
class BindResult:
    tool_id: str
    signature_valid: bool
    signature_reason: str
    drift: DriftResult
    accepted: bool
    reasons: list[str]


class TrustLayer:
    """
    Usage:
        tl = TrustLayer()
        tl.attest(tool_id, invoke_spec, private_key_bytes)   # at registration time
        result = tl.bind(tool_id, invoke_spec, expected_public_key_b64)  # at every bind
    """

    def __init__(self) -> None:
        self._baselines: dict[str, dict[str, Any]] = {}  # tool_id -> signed manifest dict
        self.audit_log = HashChainAuditLog()

    def attest(self, tool_id: str, invoke_spec: dict[str, Any], private_key_bytes: bytes) -> SignedManifest:
        manifest = spec_to_manifest(invoke_spec)
        signed = sign_manifest(manifest, private_key_bytes, key_id=tool_id)
        self._baselines[tool_id] = signed.to_dict()
        self.audit_log.append({"action": "attest", "tool_id": tool_id, "manifest": manifest})
        return signed

    def bind(
        self,
        tool_id: str,
        current_invoke_spec: dict[str, Any],
        expected_public_key_b64: str,
        current_signed_dict: dict[str, Any] | None = None,
    ) -> BindResult:
        """
        Verify a tool at bind time.

        current_signed_dict: the signed manifest as currently declared by
        the tool server (what an attacker could tamper with, strip, or
        replay). If None, verification runs against an unsigned reduction
        of current_invoke_spec (simulating a server with no attestation
        at all -- always rejected under a signature-required policy).
        """
        reasons: list[str] = []
        current_manifest = spec_to_manifest(current_invoke_spec)

        if current_signed_dict is None:
            sig_result = type("R", (), {"valid": False, "reason": "no signature present"})()
        else:
            sig_result = verify_manifest(current_signed_dict, expected_public_key_b64)

        if not sig_result.valid:
            reasons.append(f"signature check failed: {sig_result.reason}")

        baseline = self._baselines.get(tool_id)
        if baseline is not None:
            baseline_manifest = {
                k: v for k, v in baseline.items() if k not in ("signature", "_meta")
            }
            drift = check_drift(baseline_manifest, current_manifest)
        else:
            drift = DriftResult(drifted=False, severity="none")

        if drift.severity == "breaking":
            reasons.append(f"breaking drift detected: {drift.changed_fields + drift.removed_fields}")

        accepted = sig_result.valid and drift.severity != "breaking"

        self.audit_log.append(
            {
                "action": "bind",
                "tool_id": tool_id,
                "accepted": accepted,
                "signature_valid": sig_result.valid,
                "drift_severity": drift.severity,
            }
        )

        return BindResult(
            tool_id=tool_id,
            signature_valid=sig_result.valid,
            signature_reason=sig_result.reason,
            drift=drift,
            accepted=accepted,
            reasons=reasons,
        )
