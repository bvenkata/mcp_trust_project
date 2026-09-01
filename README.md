# mcp-trust

Attestation and drift-detection layer for binding to MCP (Model Context
Protocol) tool servers.

`mcp-trust` lets an agent, orchestrator, or connector layer (such as
[mcp-api-connect](https://github.com/bvenkata/mcp-api-connect)) verify,
at bind time, that a tool server's declared identity and capability
schema are cryptographically authentic and unchanged since they were
last approved — rather than trusting a tool's self-declared manifest at
face value on every call.

## What it does

1. **Ed25519 signing** of a tool's identity/capability manifest (target,
   auth type, request/response schema) — never the credentials themselves.
2. **Hash-chain audit log** of bind-time decisions, so any retroactive
   edit to stored log entries is detectable.
3. **Schema drift detection** at bind time, classifying changes since the
   last attested baseline as *additive* (safe) or *breaking* (e.g. an
   auth-type downgrade, a removed response field — a "rug pull").

## What it does not claim to do

- It is not a general anti-replay/freshness mechanism. Replay of a
  manifest that is still identical to the current baseline is accepted
  (this is correct — it isn't an attack). Replay of a stale manifest is
  caught only when it would hide a change that has since legitimately
  occurred, via drift detection, not a nonce or version counter.
- It does not defend against a legitimately-signed tool that is
  malicious by design, compromise of the signing key itself, or
  compromise of the host application. See the threat model in the
  accompanying paper (citation below) for the full scope.

## Evaluation

`eval_harness.py` runs a synthetic testbed of 20 connector manifests
through five injected attack scenarios (signature stripping, invalid
signatures, key substitution, rug-pull auth downgrades, schema removal)
plus false-positive and replay-boundary tests. Run it yourself:

```bash
pip install cryptography
python3 eval_harness.py
```

Full methodology and results are described in the accompanying paper
(see Citation).

## Tests

```bash
pip install pytest cryptography
python3 -m pytest tests/ -v
```

## Status

Early-stage reference implementation, built to accompany a research
paper on applying enterprise integration-architecture patterns to MCP
trust boundaries. Not yet production-hardened; contributions and issue
reports welcome.

## Citation

See `CITATION.cff`. If this paper has not yet been assigned a DOI/venue
entry, cite the GitHub repository directly.

## License

See `LICENSE`.
