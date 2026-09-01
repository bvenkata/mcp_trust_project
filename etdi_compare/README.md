# RQ3 Comparative Evaluation

Two comparisons, of two different kinds — read the distinction carefully
before citing either.

## 1. vs. ETDI — real comparison, unmodified original code

`etdi_types.py`, `rug_pull_prevention.py`, and `exceptions.py` are copied
**verbatim, unmodified**, from ETDI's own reference implementation:
https://github.com/vineethsai/python-sdk (the code cited by the ETDI
paper, arXiv:2506.01333). They are relocated here only so they can be
imported standalone without pulling in the full MCP SDK dependency
tree. `ETDI_ORIGINAL_LICENSE.txt` is that repo's MIT license, included
per its terms.

`run_comparison.py` runs both mcp-trust and ETDI's actual
`RugPullDetector` against the same 20-manifest synthetic testbed used
in the main evaluation (`../eval_harness.py`).

**Scope note:** ETDI's full identity-verification path
(`ETDIVerifier.verify_tool`) requires a live OAuth provider (Okta/
Auth0/Azure) by design and is not exercised here. What's compared is
the drift/rug-pull detection logic (`RugPullDetector`), which — like
mcp-trust's drift module — operates on local schema hashing and needs
no external infrastructure. This is a real architectural difference,
not a limitation of the test: mcp-trust's signing/drift layer is
self-contained; ETDI's identity layer depends on external OAuth
infrastructure by design.

**Result:** ETDI's `RugPullDetector` correctly flags 100% (20/20) of
both tested breaking-change attacks. On benign, additive, backward-
compatible changes, its false-positive rate depends entirely on
whether the operator bumps the tool's version string: 100% (20/20)
false-positive rate when the version is left unchanged, 0% when it is
incremented — exactly matching ETDI's documented versioning
discipline. mcp-trust classifies additive vs. breaking changes
directly from the manifest content and does not require a version-bump
convention to avoid false positives. This is a genuine trade-off, not
a strict superiority claim in either direction: ETDI's design assumes
and rewards operator versioning discipline; mcp-trust does not require
it but also has no equivalent to ETDI's OAuth-backed identity
guarantees.

## 2. vs. AttestMCP — labeled reproduction, NOT original code

AttestMCP (Maloyan & Namiot, arXiv:2601.17549) describes but does not
release an implementation — there is no public repository to compare
against directly. `attestmcp_repro.py` reproduces their published
design (Section VI-A/VI-C: capability certificates, HMAC-SHA256 message
authentication, nonce + timestamp replay protection) from the paper
text. Any implementation detail the paper doesn't fully specify (e.g.,
the capability-certificate signing algorithm) is our own choice, noted
inline in the code, and should not be attributed to the original
authors.

`run_attestmcp_repro.py` runs this reproduction against the same
testbed. **Result:** the reproduction detects 100% (20/20) of message
tampering, replay, capability-escalation, and expired-certificate
scenarios, with 0% false positives on legitimate messages, and adds
~0.014ms median overhead for the HMAC sign+verify+nonce-check path
alone (excluding certificate validation, which the original paper
reports separately and which we did not re-measure, since our
certificate format differs from theirs).

## Running it yourself

```bash
pip install cryptography
python3 run_comparison.py
python3 run_attestmcp_repro.py
```
