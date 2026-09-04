"""
examples/order_detail_api.py
----------------------------
End-to-end walkthrough of putting an "order detail" REST API behind the
mcp-trust bind-time verification layer.

Scenario: an agent needs to call GET /v1/orders/{order_id} on a partner
commerce service. We attest that connector once at registration, then
verify it on every bind. We then show three later binds:

    1. unchanged tool            -> accepted
    2. benign additive change    -> accepted  (new optional response field)
    3. rug pull                  -> rejected  (auth downgraded api_key -> none)

Run:
    pip install cryptography
    python3 examples/order_detail_api.py
"""
from __future__ import annotations

import base64
import copy

from mcp_trust import TrustLayer, generate_keypair, sign_manifest
from mcp_trust.trust_layer import spec_to_manifest


TOOL_ID = "partner-commerce:order-detail"

# ---------------------------------------------------------------------------
# 1. The connector definition (mcp-api-connect style InvokeSpec).
#    Note `auth.config` carries a live secret -- spec_to_manifest() strips it
#    before anything is signed or logged.
# ---------------------------------------------------------------------------
ORDER_DETAIL_SPEC = {
    "target": {
        "base_url": "https://api.partner-commerce.com",
        "protocol": "rest",
    },
    "auth": {
        "type": "api_key",
        "config": {"api_key": "sk_live_do_not_sign_me"},  # never attested
    },
    "request_format": {
        "method": "GET",
        "path": "/v1/orders/{order_id}",
        "path_params": {"order_id": "string"},
        "query_params": {"include": "string?"},   # optional: "line_items,shipping"
        "content_type": "json",
    },
    "response_format": {
        "content_type": "json",
        "fields": {
            "order_id": "string",
            "status": "string",
            "currency": "string",
            "total": "number",
            "customer_email": "string",
            "line_items": "array",
        },
    },
}


def show(title: str, result) -> None:
    print(f"\n=== {title} ===")
    print(f"  accepted        : {result.accepted}")
    print(f"  signature_valid : {result.signature_valid} ({result.signature_reason})")
    print(f"  drift severity  : {result.drift.severity}")
    if result.drift.drifted:
        print(f"    added   : {result.drift.added_fields}")
        print(f"    changed : {result.drift.changed_fields}")
        print(f"    removed : {result.drift.removed_fields}")
    if result.reasons:
        print(f"  reasons         : {result.reasons}")


def main() -> None:
    tl = TrustLayer()

    # The tool vendor holds the private key; the agent pins the public key.
    priv, pub = generate_keypair()
    pinned_pub_b64 = base64.b64encode(pub).decode()

    # -- registration time: attest the baseline once -------------------------
    baseline_signed = tl.attest(TOOL_ID, ORDER_DETAIL_SPEC, priv)
    print(f"attested {TOOL_ID}")
    print(f"  manifest signed = {spec_to_manifest(ORDER_DETAIL_SPEC)}")

    # -- bind #1: tool server presents the same signed manifest -------------
    r1 = tl.bind(
        TOOL_ID,
        ORDER_DETAIL_SPEC,
        pinned_pub_b64,
        current_signed_dict=baseline_signed.to_dict(),
    )
    show("bind #1  unchanged tool", r1)

    # -- bind #2: vendor adds an optional response field, re-signs ----------
    additive_spec = copy.deepcopy(ORDER_DETAIL_SPEC)
    additive_spec["response_format"]["fields"]["refunded_amount"] = "number"
    additive_signed = sign_manifest(
        spec_to_manifest(additive_spec), priv, key_id=TOOL_ID
    )
    r2 = tl.bind(
        TOOL_ID,
        additive_spec,
        pinned_pub_b64,
        current_signed_dict=additive_signed.to_dict(),
    )
    show("bind #2  benign additive change (new response field)", r2)

    # -- bind #3: rug pull -- auth downgraded to none, validly re-signed ----
    rugged_spec = copy.deepcopy(ORDER_DETAIL_SPEC)
    rugged_spec["auth"] = {"type": "none"}
    rugged_spec["response_format"]["fields"].pop("customer_email")  # field removed
    rugged_signed = sign_manifest(
        spec_to_manifest(rugged_spec), priv, key_id=TOOL_ID
    )
    r3 = tl.bind(
        TOOL_ID,
        rugged_spec,
        pinned_pub_b64,
        current_signed_dict=rugged_signed.to_dict(),
    )
    show("bind #3  RUG PULL (auth downgrade + removed field)", r3)

    # -- bind #4: attacker strips the signature entirely -------------------
    r4 = tl.bind(TOOL_ID, ORDER_DETAIL_SPEC, pinned_pub_b64, current_signed_dict=None)
    show("bind #4  signature stripped", r4)

    # -- the audit trail --------------------------------------------------
    valid, broken_at = tl.audit_log.verify()
    print(f"\naudit log: {len(tl.audit_log.entries)} entries, "
          f"intact={valid}, first_broken_index={broken_at}")
    for e in tl.audit_log.entries:
        print(f"  [{e.index}] {e.event}")


if __name__ == "__main__":
    main()
