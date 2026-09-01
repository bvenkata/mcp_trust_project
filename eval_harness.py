"""
Evaluation harness for mcp_trust, producing real (not placeholder) numbers
for Section VI of the paper: RQ1 (detection efficacy / false-positive rate)
and RQ2 (overhead).

Testbed: N synthetic connector manifests, shaped like real mcp-api-connect
InvokeSpecs (different target base_urls, protocols, auth types, and
request/response schemas), standing in for a population of MCP tool
servers. This is a synthetic testbed, not real production MCP servers --
that scope limitation is stated explicitly in the paper text this feeds.
"""
from __future__ import annotations

import copy
import statistics
import time

from mcp_trust import generate_keypair, sign_manifest, TrustLayer
from mcp_trust.signing import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64

N_SERVERS = 20

def make_synthetic_specs(n: int) -> list[dict]:
    protocols = ["rest", "rest", "rest", "soap"]
    auth_types = ["api_key", "bearer", "basic", "oauth2_client_credentials"]
    specs = []
    for i in range(n):
        specs.append({
            "target": {
                "base_url": f"https://partner{i}.example.com/api",
                "protocol": protocols[i % len(protocols)],
            },
            "auth": {
                "type": auth_types[i % len(auth_types)],
                "config": {"api_key": f"secret-{i}"},  # never signed/logged, see spec_to_manifest
            },
            "request_format": {
                "method": "POST",
                "path": f"/v1/resource{i % 5}",
                "content_type": "json",
                "field_map": {"target.id": "$.source.id", "target.amount": "$.source.amount"},
            },
            "response_format": {"content_type": "json"},
        })
    return specs


def scenario_signature_stripping(signed_dict: dict) -> dict:
    d = copy.deepcopy(signed_dict)
    del d["signature"]
    return d


def scenario_invalid_signature(signed_dict: dict) -> dict:
    d = copy.deepcopy(signed_dict)
    d["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    return d


def scenario_key_substitution(signed_dict: dict) -> dict:
    """Attacker generates their own keypair and re-signs the (possibly
    modified) manifest with it -- tests whether pinned-key verification
    catches an attacker who controls both content and signature but not
    the legitimate private key."""
    manifest = {k: v for k, v in signed_dict.items() if k not in ("signature", "_meta")}
    attacker_priv = Ed25519PrivateKey.generate()
    attacker_pub = attacker_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    sig = attacker_priv.sign(canonicalize(manifest))
    out = dict(manifest)
    out["signature"] = base64.b64encode(sig).decode("ascii")
    out["_meta"] = {"public_key": base64.b64encode(attacker_pub).decode("ascii"), "signed_at": time.time(), "key_id": "attacker"}
    return out


def scenario_breaking_schema_change(spec: dict) -> dict:
    """Simulates a 'rug pull': auth type silently changes after approval."""
    d = copy.deepcopy(spec)
    d["auth"]["type"] = "none"
    return d


def scenario_removed_field(spec: dict) -> dict:
    d = copy.deepcopy(spec)
    d["response_format"] = {}
    return d


def scenario_benign_additive_change(spec: dict) -> dict:
    """Legitimate, backward-compatible change: a new optional field is added.
    This should NOT be flagged as breaking -- used for the false-positive test."""
    d = copy.deepcopy(spec)
    d["request_format"]["field_map"]["target.new_optional_field"] = "$.source.new_field"
    return d


def scenario_replay_stale(old_signed_dict: dict) -> dict:
    """Attacker replays a previously-valid signed manifest after the tool
    legitimately rotated to a new one. Signature is technically valid;
    this is the specific gap mcp-attest's threat model (paper Section V.A)
    notes it does NOT fully solve without a monotonic version/nonce -- we
    test it here honestly rather than assuming success."""
    return copy.deepcopy(old_signed_dict)


def run_rq1():
    specs = make_synthetic_specs(N_SERVERS)
    tl = TrustLayer()
    keys = {}
    signed_baselines = {}

    for i, spec in enumerate(specs):
        priv, pub = generate_keypair()
        keys[i] = (priv, base64.b64encode(pub).decode("ascii"))
        signed = tl.attest(str(i), spec, priv)
        signed_baselines[i] = signed.to_dict()

    detected = 0
    total_attacks = 0
    detail = []

    # Attack scenarios (should be detected / rejected)
    attack_defs = [
        ("signature_stripping", lambda i: scenario_signature_stripping(signed_baselines[i])),
        ("invalid_signature", lambda i: scenario_invalid_signature(signed_baselines[i])),
        ("key_substitution", lambda i: scenario_key_substitution(signed_baselines[i])),
    ]
    for name, fn in attack_defs:
        for i in range(N_SERVERS):
            tampered_signed = fn(i)
            result = tl.bind(str(i), specs[i], keys[i][1], current_signed_dict=tampered_signed)
            total_attacks += 1
            ok = not result.accepted
            detected += int(ok)
            detail.append((name, i, ok))

    # Breaking schema-change attacks (rug pull) -- valid signature on NEW
    # content signed by legit key would require attacker to hold the key,
    # which is out of scope per threat model; realistic version: server
    # operator (or compromised server) re-signs a breaking change with its
    # own legitimate key -- drift detection is what catches this, not signing.
    for i in range(N_SERVERS):
        mutated_spec = scenario_breaking_schema_change(specs[i])
        re_signed = sign_manifest(
            {k: v for k, v in signed_baselines[i].items() if k not in ("signature", "_meta")} | {},
            keys[i][0],
        )
        # actually sign the mutated manifest, not the old one
        from mcp_trust.trust_layer import spec_to_manifest
        mutated_manifest = spec_to_manifest(mutated_spec)
        re_signed = sign_manifest(mutated_manifest, keys[i][0], key_id=str(i))
        result = tl.bind(str(i), mutated_spec, keys[i][1], current_signed_dict=re_signed.to_dict())
        total_attacks += 1
        ok = not result.accepted  # should be rejected due to breaking drift
        detected += int(ok)
        detail.append(("breaking_auth_change_rug_pull", i, ok))

    for i in range(N_SERVERS):
        mutated_spec = scenario_removed_field(specs[i])
        from mcp_trust.trust_layer import spec_to_manifest
        mutated_manifest = spec_to_manifest(mutated_spec)
        re_signed = sign_manifest(mutated_manifest, keys[i][0], key_id=str(i))
        result = tl.bind(str(i), mutated_spec, keys[i][1], current_signed_dict=re_signed.to_dict())
        total_attacks += 1
        ok = not result.accepted
        detected += int(ok)
        detail.append(("removed_response_schema", i, ok))

    # Replay-stale (documented as a known gap, expect this to NOT be reliably caught)
    replay_detected = 0
    for i in range(N_SERVERS):
        # legit rotation: server signs a benign additive update
        from mcp_trust.trust_layer import spec_to_manifest
        updated_spec = scenario_benign_additive_change(specs[i])
        updated_manifest = spec_to_manifest(updated_spec)
        new_signed = sign_manifest(updated_manifest, keys[i][0], key_id=str(i))
        tl.attest(str(i), updated_spec, keys[i][0])  # baseline moves forward
        # attacker replays the OLD signed manifest
        replayed = scenario_replay_stale(signed_baselines[i])
        result = tl.bind(str(i), specs[i], keys[i][1], current_signed_dict=replayed)
        replay_caught = not result.accepted
        replay_detected += int(replay_caught)

    # Pure replay of a manifest that is STILL IDENTICAL to the current
    # baseline (nothing has rotated). This should be ACCEPTED -- resending
    # an unchanged, validly-signed manifest is not itself an attack, and a
    # system that flags it would be crying wolf. This distinguishes "we
    # catch replay of a manifest that hides a since-occurred change" from
    # "we solve general replay/freshness," which the threat model does not
    # claim.
    tl3 = TrustLayer()
    pure_replay_false_alarms = 0
    for i in range(N_SERVERS):
        priv3, pub3 = generate_keypair()
        pub3_b64 = base64.b64encode(pub3).decode("ascii")
        signed3 = tl3.attest(str(i), specs[i], priv3)
        # "replay" the exact same still-current signed manifest
        result = tl3.bind(str(i), specs[i], pub3_b64, current_signed_dict=signed3.to_dict())
        if not result.accepted:
            pure_replay_false_alarms += 1

    # False-positive test: benign additive changes should NOT be rejected
    fp_specs = make_synthetic_specs(N_SERVERS)  # fresh set, independent baselines
    tl2 = TrustLayer()
    fp_keys = {}
    for i, spec in enumerate(fp_specs):
        priv, pub = generate_keypair()
        fp_keys[i] = (priv, base64.b64encode(pub).decode("ascii"))
        tl2.attest(str(i), spec, priv)

    false_positives = 0
    for i in range(N_SERVERS):
        from mcp_trust.trust_layer import spec_to_manifest
        updated_spec = scenario_benign_additive_change(fp_specs[i])
        updated_manifest = spec_to_manifest(updated_spec)
        re_signed = sign_manifest(updated_manifest, fp_keys[i][0], key_id=str(i))
        result = tl2.bind(str(i), updated_spec, fp_keys[i][1], current_signed_dict=re_signed.to_dict())
        if not result.accepted:
            false_positives += 1

    return {
        "n_servers": N_SERVERS,
        "attack_scenarios_run": total_attacks,
        "attacks_detected": detected,
        "detection_rate_pct": round(100 * detected / total_attacks, 1),
        "replay_stale_after_rotation_detected": replay_detected,
        "replay_stale_after_rotation_total": N_SERVERS,
        "replay_stale_after_rotation_detection_rate_pct": round(100 * replay_detected / N_SERVERS, 1),
        "replay_stale_note": "Detected via drift-vs-current-baseline, not a nonce/freshness mechanism -- catches replay that hides a since-occurred change, not general replay.",
        "pure_unchanged_replay_false_alarms": pure_replay_false_alarms,
        "pure_unchanged_replay_total": N_SERVERS,
        "pure_unchanged_replay_false_alarm_rate_pct": round(100 * pure_replay_false_alarms / N_SERVERS, 1),
        "false_positive_count": false_positives,
        "false_positive_total": N_SERVERS,
        "false_positive_rate_pct": round(100 * false_positives / N_SERVERS, 1),
        "detail_sample": detail[:5],
    }


def run_rq2(n_trials: int = 500):
    specs = make_synthetic_specs(5)
    priv, pub = generate_keypair()
    pub_b64 = base64.b64encode(pub).decode("ascii")

    from mcp_trust.trust_layer import spec_to_manifest
    manifest = spec_to_manifest(specs[0])

    # Cold: sign + verify from scratch each time (simulates first bind)
    cold_times = []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        signed = sign_manifest(manifest, priv)
        from mcp_trust.signing import verify_manifest
        verify_manifest(signed.to_dict(), pub_b64)
        t1 = time.perf_counter()
        cold_times.append((t1 - t0) * 1000)  # ms

    # Warm: verify only (signature + manifest already produced, simulates
    # repeated binds to an already-attested, unchanged tool)
    signed = sign_manifest(manifest, priv)
    signed_dict = signed.to_dict()
    from mcp_trust.signing import verify_manifest
    warm_times = []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        verify_manifest(signed_dict, pub_b64)
        t1 = time.perf_counter()
        warm_times.append((t1 - t0) * 1000)

    # Baseline: unsigned invocation with no trust layer at all (dict lookup)
    baseline_times = []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        _ = specs[0]["target"]["base_url"]
        t1 = time.perf_counter()
        baseline_times.append((t1 - t0) * 1000)

    def stats(xs):
        return {
            "median_ms": round(statistics.median(xs), 4),
            "mean_ms": round(statistics.mean(xs), 4),
            "p95_ms": round(sorted(xs)[int(0.95 * len(xs))], 4),
        }

    return {
        "n_trials": n_trials,
        "cold_sign_and_verify": stats(cold_times),
        "warm_verify_only": stats(warm_times),
        "baseline_no_trust_layer": stats(baseline_times),
    }


if __name__ == "__main__":
    import json
    print("=== RQ1: Detection Efficacy ===")
    rq1 = run_rq1()
    print(json.dumps(rq1, indent=2))
    print()
    print("=== RQ2: Overhead ===")
    rq2 = run_rq2()
    print(json.dumps(rq2, indent=2))
