"""
Real head-to-head comparison: mcp-trust vs. ETDI's actual, unmodified
rug-pull detection code (copied verbatim from
https://github.com/vineethsai/python-sdk, the ETDI paper's own reference
implementation — files etdi_types.py and rug_pull_prevention.py in this
directory are byte-identical to that repo's src/mcp/etdi/{types,rug_pull_prevention}.py,
only relocated for standalone import).

SCOPE HONESTLY STATED: ETDI's full identity-verification path
(ETDIVerifier.verify_tool) requires a live OAuth provider (Okta/Auth0/
Azure) and is not exercised here — that is a real architectural
dependency of ETDI's design, not an omission on our part. What IS
directly comparable and tested here is the drift/rug-pull detection
logic (RugPullDetector), which — like mcp-trust's drift module — operates
on local tool-definition hashing and does not require live
infrastructure. Signature-based attacks (stripping, invalid signature,
key substitution) are therefore not run against ETDI in this harness;
they are ETDI's OAuth layer's job, not RugPullDetector's, and are noted
as such in the results.
"""
import sys, os
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)  # mcp_trust_project/ (this dir's parent)
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, _HERE)

from rug_pull_prevention import RugPullDetector
from etdi_types import ETDIToolDefinition, Permission

from eval_harness import make_synthetic_specs, N_SERVERS
from mcp_trust.trust_layer import spec_to_manifest


def spec_to_etdi_tool(spec: dict, tool_id: str, version: str = "1.0.0") -> ETDIToolDefinition:
    """Adapt our synthetic InvokeSpec into an ETDIToolDefinition, mapping
    fields as directly as the two schemas allow."""
    auth_type = spec["auth"]["type"]
    permissions = [
        Permission(name="auth", description=f"Authentication via {auth_type}", scope=f"auth:{auth_type}")
    ]
    return ETDIToolDefinition(
        id=tool_id,
        name=f"connector-{tool_id}",
        version=version,
        description=f"Connector for {spec['target']['base_url']}",
        provider={"name": "test-provider", "type": spec["target"]["protocol"]},
        schema={
            "input": spec["request_format"],
            "output": spec["response_format"],
        },
        permissions=permissions,
    )


def run_etdi_comparison():
    specs = make_synthetic_specs(N_SERVERS)
    detector = RugPullDetector(strict_mode=True)

    results = {}

    # --- Scenario A: breaking auth downgrade (maps to permission removal) ---
    detected_a = 0
    for i in range(N_SERVERS):
        tool = spec_to_etdi_tool(specs[i], str(i))
        integrity = detector.create_implementation_integrity(tool)

        mutated_spec = dict(specs[i])
        mutated_spec["auth"] = {"type": "none"}
        mutated_tool = spec_to_etdi_tool(mutated_spec, str(i), version="1.0.0")  # same version, no bump
        mutated_tool.permissions = []  # auth permission removed entirely

        result = detector.detect_rug_pull(mutated_tool, integrity)
        if result.is_rug_pull:
            detected_a += 1
    results["breaking_auth_downgrade"] = {"detected": detected_a, "total": N_SERVERS}

    # --- Scenario B: removed response schema ---
    detected_b = 0
    for i in range(N_SERVERS):
        tool = spec_to_etdi_tool(specs[i], str(i))
        integrity = detector.create_implementation_integrity(tool)

        mutated_spec = dict(specs[i])
        mutated_spec["response_format"] = {}
        mutated_tool = spec_to_etdi_tool(mutated_spec, str(i), version="1.0.0")  # same version, no bump

        result = detector.detect_rug_pull(mutated_tool, integrity)
        if result.is_rug_pull:
            detected_b += 1
    results["removed_response_schema"] = {"detected": detected_b, "total": N_SERVERS}

    # --- False-positive test: benign additive change, no version bump
    #     (identical convention to the mcp-trust false-positive test) ---
    false_positives = 0
    for i in range(N_SERVERS):
        tool = spec_to_etdi_tool(specs[i], str(i))
        integrity = detector.create_implementation_integrity(tool)

        mutated_spec = dict(specs[i])
        mutated_spec["request_format"] = dict(specs[i]["request_format"])
        mutated_spec["request_format"]["field_map"] = dict(specs[i]["request_format"]["field_map"])
        mutated_spec["request_format"]["field_map"]["target.new_optional_field"] = "$.source.new_field"
        mutated_tool = spec_to_etdi_tool(mutated_spec, str(i), version="1.0.0")  # no version bump

        result = detector.detect_rug_pull(mutated_tool, integrity)
        if result.is_rug_pull:
            false_positives += 1
    results["false_positive_no_version_bump"] = {"flagged": false_positives, "total": N_SERVERS}

    # --- Same false-positive test, but WITH version bump (as ETDI's
    #     documented discipline expects operators to do for any change) ---
    false_positives_versioned = 0
    for i in range(N_SERVERS):
        tool = spec_to_etdi_tool(specs[i], str(i), version="1.0.0")
        integrity = detector.create_implementation_integrity(tool)

        mutated_spec = dict(specs[i])
        mutated_spec["request_format"] = dict(specs[i]["request_format"])
        mutated_spec["request_format"]["field_map"] = dict(specs[i]["request_format"]["field_map"])
        mutated_spec["request_format"]["field_map"]["target.new_optional_field"] = "$.source.new_field"
        mutated_tool = spec_to_etdi_tool(mutated_spec, str(i), version="1.1.0")  # version bumped

        result = detector.detect_rug_pull(mutated_tool, integrity)
        if result.is_rug_pull:
            false_positives_versioned += 1
    results["false_positive_with_version_bump"] = {"flagged": false_positives_versioned, "total": N_SERVERS}

    return results


if __name__ == "__main__":
    import json
    print("=== ETDI (real, unmodified RugPullDetector code) — comparison results ===")
    r = run_etdi_comparison()
    print(json.dumps(r, indent=2))
