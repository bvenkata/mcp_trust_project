"""
Evaluates attestmcp_repro.py (our labeled reproduction of AttestMCP's
published design) against the same 20-server testbed and comparable
attack scenarios used for mcp-trust and ETDI, for RQ3.
"""
import sys, os, time, statistics
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)  # mcp_trust_project/ (this dir's parent)
sys.path.insert(0, _HERE)
sys.path.insert(0, _PROJECT_ROOT)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attestmcp_repro import (
    ca_issue_certificate, verify_certificate, check_capability,
    sign_message, verify_message, NonceStore,
)
from eval_harness import make_synthetic_specs, N_SERVERS

import secrets


def run_attestmcp_repro_eval():
    specs = make_synthetic_specs(N_SERVERS)
    ca_key = Ed25519PrivateKey.generate()
    ca_pub = ca_key.public_key()

    certs = {}
    secrets_map = {}
    for i, spec in enumerate(specs):
        capabilities = [f"invoke:{spec['request_format']['path']}"]
        certs[i] = ca_issue_certificate(str(i), capabilities, ca_key)
        secrets_map[i] = secrets.token_bytes(32)

    results = {}

    # --- Scenario: message tampering (content altered post-signing) ---
    detected = 0
    nonce_store = NonceStore()
    for i in range(N_SERVERS):
        message = {"action": specs[i]["request_format"]["path"], "payload": {"x": 1}}
        ts, nonce = time.time(), secrets.token_hex(16)
        mac = sign_message(message, str(i), ts, nonce, secrets_map[i])
        tampered = dict(message)
        tampered["payload"] = {"x": 999}  # tamper after signing
        ok, reason = verify_message(tampered, str(i), ts, nonce, mac, secrets_map[i], nonce_store)
        if not ok:
            detected += 1
    results["message_tampering"] = {"detected": detected, "total": N_SERVERS}

    # --- Scenario: replay attack (valid message resent) ---
    detected = 0
    nonce_store = NonceStore()
    for i in range(N_SERVERS):
        message = {"action": specs[i]["request_format"]["path"], "payload": {"x": 1}}
        ts, nonce = time.time(), secrets.token_hex(16)
        mac = sign_message(message, str(i), ts, nonce, secrets_map[i])
        ok1, _ = verify_message(message, str(i), ts, nonce, mac, secrets_map[i], nonce_store)
        ok2, reason2 = verify_message(message, str(i), ts, nonce, mac, secrets_map[i], nonce_store)  # replay
        if ok1 and not ok2:
            detected += 1
    results["replay_attack"] = {"detected": detected, "total": N_SERVERS}

    # --- Scenario: capability escalation (action outside signed cert) ---
    detected = 0
    for i in range(N_SERVERS):
        allowed = check_capability(certs[i], f"invoke:{specs[i]['request_format']['path']}")
        escalated = check_capability(certs[i], "invoke:/admin/delete-all")
        if allowed and not escalated:
            detected += 1
    results["capability_escalation"] = {"detected": detected, "total": N_SERVERS}

    # --- Scenario: expired certificate ---
    detected = 0
    for i in range(N_SERVERS):
        capabilities = [f"invoke:{specs[i]['request_format']['path']}"]
        expired_cert = ca_issue_certificate(str(i), capabilities, ca_key, validity_seconds=-1)
        ok, reason = verify_certificate(expired_cert, ca_pub)
        if not ok:
            detected += 1
    results["expired_certificate"] = {"detected": detected, "total": N_SERVERS}

    # --- False positive test: legitimate fresh message, correctly signed ---
    false_positives = 0
    nonce_store = NonceStore()
    for i in range(N_SERVERS):
        message = {"action": specs[i]["request_format"]["path"], "payload": {"x": 1}}
        ts, nonce = time.time(), secrets.token_hex(16)
        mac = sign_message(message, str(i), ts, nonce, secrets_map[i])
        ok, reason = verify_message(message, str(i), ts, nonce, mac, secrets_map[i], nonce_store)
        if not ok:
            false_positives += 1
    results["false_positive_legit_message"] = {"flagged": false_positives, "total": N_SERVERS}

    # --- Overhead: HMAC sign+verify, measured on our own hardware ---
    n_trials = 500
    message = {"action": "/v1/resource0", "payload": {"x": 1}}
    secret = secrets.token_bytes(32)
    times = []
    ns = NonceStore()
    for _ in range(n_trials):
        t0 = time.perf_counter()
        ts, nonce = time.time(), secrets.token_hex(16)
        mac = sign_message(message, "bench", ts, nonce, secret)
        verify_message(message, "bench", ts, nonce, mac, secret, ns)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)
    results["overhead_ms"] = {
        "median": round(statistics.median(times), 4),
        "mean": round(statistics.mean(times), 4),
        "p95": round(sorted(times)[int(0.95 * len(times))], 4),
        "note": "HMAC sign+verify+nonce-check only; excludes certificate validation, which the original paper reports separately (4.2ms P50 cold / 0.3ms cached) and which we did not re-measure since our reproduction's cert format differs from theirs.",
    }

    return results


if __name__ == "__main__":
    import json
    print("=== AttestMCP reproduction (from published design, NOT original code) ===")
    print(json.dumps(run_attestmcp_repro_eval(), indent=2))
