"""
mcp_trust.drift
----------------
Compares a tool/connector's currently-declared manifest against its last
attested (signed) baseline, classifying differences as additive (unlikely
to be malicious -- new optional capability) or breaking/suspicious
(removed capability, changed auth type, changed target, changed required
fields -- exactly the shape of a "rug pull" per ETDI's terminology).

This is a heuristic field-level diff, not a semantic understanding of the
API -- it flags *that* something changed and *how*, and leaves the
significance judgment to the operator or a policy layer (out of scope,
same boundary the paper draws around mcp-attest's original threat model).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Fields whose change is considered high-severity (auth/target/security-relevant)
BREAKING_KEY_PREFIXES = ("auth.", "target.base_url", "target.protocol")


@dataclass
class DriftResult:
    drifted: bool
    severity: str  # "none" | "additive" | "breaking"
    changed_fields: list[str] = field(default_factory=list)
    added_fields: list[str] = field(default_factory=list)
    removed_fields: list[str] = field(default_factory=list)


def _flatten(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, prefix=f"{key}."))
        else:
            out[key] = v
    return out


def check_drift(baseline_manifest: dict[str, Any], current_manifest: dict[str, Any]) -> DriftResult:
    base_flat = _flatten(baseline_manifest)
    cur_flat = _flatten(current_manifest)

    base_keys = set(base_flat.keys())
    cur_keys = set(cur_flat.keys())

    added = sorted(cur_keys - base_keys)
    removed = sorted(base_keys - cur_keys)
    changed = sorted(
        k for k in (base_keys & cur_keys) if base_flat[k] != cur_flat[k]
    )

    if not added and not removed and not changed:
        return DriftResult(drifted=False, severity="none")

    all_touched = set(added) | set(removed) | set(changed)
    is_breaking = bool(removed) or any(
        any(t.startswith(p) for p in BREAKING_KEY_PREFIXES) for t in all_touched
    )

    severity = "breaking" if is_breaking else "additive"
    return DriftResult(
        drifted=True,
        severity=severity,
        changed_fields=changed,
        added_fields=added,
        removed_fields=removed,
    )
