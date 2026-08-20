# RulePack release lifecycle

A RulePack is the signed, versioned unit of runtime detection content. It binds the rules themselves to the compatibility and release evidence needed to decide whether that exact content may move from candidate to canary and then to production.

This lifecycle is deliberately separate from agent update distribution. RulePack signing and release decisions live here; secure distribution and wire-side anti-downgrade enforcement are the responsibility of the fleet update path.

## What a RulePack binds

A RulePack includes:

- a stable pack ID, monotonically increasing pack version, and canonical SHA-256 digest;
- typed `detection.Rule` definitions;
- the minimum agent version and accepted telemetry schema versions;
- required sensor versions and matcher fields;
- ATT&CK mappings;
- positive and negative replay fixtures;
- per-rule latency/CPU budgets;
- suppression policy, rollout cohorts, and rollback target.

Construction is fail-closed. Required fields must cover every field used by a rule matcher, ATT&CK mappings must point at rules in the pack, fixture expectations must name rules in the pack, positive fixtures must collectively exercise every rule, and each rule must have an explicit cost budget. Set-like inputs are canonicalized for the digest so declaration order does not create a different identity.

## Trust model

RulePack signatures use Ed25519 over a domain-separated canonical RulePack encoding. The canonical digest is SHA-256 over that same normalized content; verification recomputes and validates the digest before verifying the signature. The signed artifact contains the key ID and signature, but it does **not** carry a public key that can declare itself trusted.

CI or an operator must supply the trusted Ed25519 public key separately. The CLI verifies that the supplied key has the expected fingerprint and that it verifies the exact canonical RulePack content. Mutating the pack after signing therefore fails digest validation and/or signature verification.

The public-key file used by the CLI is standard-base64 text for the raw 32-byte Ed25519 public key.

## CLI

All commands verify the signature against the externally pinned key before doing any other RulePack work.

```sh
synapse-cli rulepack verify \
  --artifact rulepack.signed.json \
  --public-key release-ed25519.pub
```

`verify` prints a small JSON identity record and exits non-zero if the pack, digest, key fingerprint, or signature is invalid.

```sh
synapse-cli rulepack replay \
  --artifact rulepack.signed.json \
  --public-key release-ed25519.pub
```

`replay` evaluates the pack's deterministic positive and negative fixtures. Positive fixtures collectively cover every rule and each fixture must fire exactly its declared rule IDs; negative fixtures must fire none. The JSON result is emitted even when a fixture fails so CI retains the evidence, and the command exits non-zero on any mismatch.

```sh
synapse-cli rulepack gate \
  --artifact rulepack.signed.json \
  --public-key release-ed25519.pub \
  --evidence rulepack-gate-evidence.json \
  --phase promotion
```

`gate` accepts `pre-canary`, `canary`, or `promotion` as the phase. It always emits the complete deterministic gate report and exits non-zero when the requested phase is not eligible.

The JSON decoder is strict: unknown fields, trailing JSON, malformed keys, and oversized inputs are rejected rather than ignored.

## Gate order

The release report evaluates the gates in this fixed order:

1. deployment compatibility;
2. positive replay;
3. negative replay;
4. per-rule performance budgets;
5. retro-hunt evidence;
6. purple/emulation and ATT&CK coverage;
7. false-positive budget;
8. canary metrics;
9. production metrics.

Passing through the false-positive budget yields `pre_canary_passed`. Passing the canary stage yields `canary_passed`. Only a report with every stage green has `passed=true` and may be used for promotion.

A failed release report never blocks rollback. Rollback still requires the RulePack's signed rollback metadata to identify the prior version correctly.

## Detection-quality metrics

Rates use integer basis points instead of floating point so CI decisions are reproducible. The report emits:

- precision and false-positive rate;
- reviewed-detection count and analyst disposition rate;
- suppression rate;
- detections per host-day (milli-detections);
- required-field availability;
- per-rule latency and CPU observations;
- measured ATT&CK coverage.

Canary and production stages re-enforce the precision/false-positive floors in addition to their host-day, detection-density, field-availability, suppression, and analyst-disposition requirements. A candidate cannot pass evaluation with good offline labels and then silently regress in production.

## Retro-hunt evidence

The existing telemetry service exposes both `Hunt` and `RetroRunRule`. RulePack release collection deliberately uses the lower-level `Hunt` seam and evaluates the **candidate RulePack rule** over the returned stored events.

That distinction matters: `RetroRunRule` uses the currently shipped detection catalogue, so using it directly to approve candidate content could test the old rule rather than the rule being promoted.

Each RulePack rule needs exactly one bounded retro case. A release window must contain context, must produce at least one candidate-rule match, and must be complete, unsampled, and free of recorded sequence gaps or losses. Each case also supplies an explicit event limit from 1 through 50,000; if the hunt returns exactly that many rows, the collector refuses the evidence because the telemetry port cannot prove there were no additional rows beyond the limit. Narrow the time window or use a larger still-bounded limit and collect again.

## Purple/emulation evidence

Purple evidence is loaded through the existing `purplecoverage.Service` trend seam and bound to one explicit tenant/engagement/run/asset scope. A `covered` row is accepted only when its measured `Actual` detections contain the expected RulePack detection; a self-asserted verdict is not sufficient. Claimed ATT&CK mappings count as covered only when that measured evidence is internally consistent, and evidence for an unclaimed detection/taxonomy pair is rejected. Missing mappings remain gaps; they are never inferred as covered.

Release tooling should persist the emitted gate report beside the signed RulePack and the underlying metric/evidence inputs so a later review can reproduce why that exact digest was admitted, promoted, or rolled back.
