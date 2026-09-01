import base64
import pytest

from mcp_trust import generate_keypair, sign_manifest, verify_manifest, HashChainAuditLog, check_drift, TrustLayer
from mcp_trust.trust_layer import spec_to_manifest


SAMPLE_SPEC = {
    "target": {"base_url": "https://api.example.com", "protocol": "rest"},
    "auth": {"type": "api_key", "config": {"api_key": "secret"}},
    "request_format": {"method": "POST", "path": "/v1/orders", "content_type": "json"},
    "response_format": {"content_type": "json"},
}


def test_sign_and_verify_roundtrip():
    priv, pub = generate_keypair()
    manifest = spec_to_manifest(SAMPLE_SPEC)
    signed = sign_manifest(manifest, priv)
    result = verify_manifest(signed.to_dict(), base64.b64encode(pub).decode())
    assert result.valid


def test_credentials_never_signed():
    manifest = spec_to_manifest(SAMPLE_SPEC)
    assert "config" not in manifest["auth"]
    assert "secret" not in str(manifest)


def test_tampered_content_fails_verification():
    priv, pub = generate_keypair()
    manifest = spec_to_manifest(SAMPLE_SPEC)
    signed = sign_manifest(manifest, priv)
    signed_dict = signed.to_dict()
    signed_dict["target"]["base_url"] = "https://evil.example.com"
    result = verify_manifest(signed_dict, base64.b64encode(pub).decode())
    assert not result.valid


def test_pinned_key_rejects_different_key():
    priv, pub = generate_keypair()
    _, other_pub = generate_keypair()
    manifest = spec_to_manifest(SAMPLE_SPEC)
    signed = sign_manifest(manifest, priv)
    result = verify_manifest(signed.to_dict(), base64.b64encode(other_pub).decode())
    assert not result.valid


def test_drift_none_for_identical_manifest():
    m = spec_to_manifest(SAMPLE_SPEC)
    d = check_drift(m, dict(m))
    assert not d.drifted
    assert d.severity == "none"


def test_drift_additive_for_new_optional_field():
    base = spec_to_manifest(SAMPLE_SPEC)
    current = spec_to_manifest(SAMPLE_SPEC)
    current["request_format"]["new_optional_field"] = "value"
    d = check_drift(base, current)
    assert d.drifted
    assert d.severity == "additive"


def test_drift_breaking_for_auth_type_change():
    base = spec_to_manifest(SAMPLE_SPEC)
    current = spec_to_manifest(SAMPLE_SPEC)
    current["auth"]["type"] = "none"
    d = check_drift(base, current)
    assert d.drifted
    assert d.severity == "breaking"


def test_audit_log_chain_valid_when_untampered():
    log = HashChainAuditLog()
    log.append({"event": "a"})
    log.append({"event": "b"})
    log.append({"event": "c"})
    valid, broken_at = log.verify()
    assert valid
    assert broken_at is None


def test_audit_log_detects_tampering():
    log = HashChainAuditLog()
    log.append({"event": "a"})
    log.append({"event": "b"})
    log.append({"event": "c"})
    log.tamper_entry_for_testing(1, {"event": "TAMPERED"})
    valid, broken_at = log.verify()
    assert not valid
    assert broken_at == 1


def test_trust_layer_accepts_unchanged_tool():
    tl = TrustLayer()
    priv, pub = generate_keypair()
    pub_b64 = base64.b64encode(pub).decode()
    signed = tl.attest("tool1", SAMPLE_SPEC, priv)
    result = tl.bind("tool1", SAMPLE_SPEC, pub_b64, current_signed_dict=signed.to_dict())
    assert result.accepted


def test_trust_layer_rejects_missing_signature():
    tl = TrustLayer()
    priv, pub = generate_keypair()
    pub_b64 = base64.b64encode(pub).decode()
    tl.attest("tool1", SAMPLE_SPEC, priv)
    result = tl.bind("tool1", SAMPLE_SPEC, pub_b64, current_signed_dict=None)
    assert not result.accepted


def test_trust_layer_rejects_breaking_drift_even_if_signed():
    tl = TrustLayer()
    priv, pub = generate_keypair()
    pub_b64 = base64.b64encode(pub).decode()
    tl.attest("tool1", SAMPLE_SPEC, priv)

    mutated_spec = dict(SAMPLE_SPEC)
    mutated_spec["auth"] = {"type": "none"}
    mutated_manifest = spec_to_manifest(mutated_spec)
    re_signed = sign_manifest(mutated_manifest, priv)  # legit key, but changed content

    result = tl.bind("tool1", mutated_spec, pub_b64, current_signed_dict=re_signed.to_dict())
    assert not result.accepted
    assert result.drift.severity == "breaking"


def test_trust_layer_accepts_benign_additive_change():
    tl = TrustLayer()
    priv, pub = generate_keypair()
    pub_b64 = base64.b64encode(pub).decode()
    tl.attest("tool1", SAMPLE_SPEC, priv)

    updated_spec = dict(SAMPLE_SPEC)
    updated_spec["request_format"] = dict(SAMPLE_SPEC["request_format"])
    updated_spec["request_format"]["new_field"] = "optional"
    updated_manifest = spec_to_manifest(updated_spec)
    re_signed = sign_manifest(updated_manifest, priv)

    result = tl.bind("tool1", updated_spec, pub_b64, current_signed_dict=re_signed.to_dict())
    assert result.accepted
    assert result.drift.severity == "additive"
