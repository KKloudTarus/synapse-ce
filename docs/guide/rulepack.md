# RulePack release lifecycle

A RulePack is the signed, versioned unit of runtime detection content. It binds the rules themselves to the compatibility and release metadata needed to decide whether that exact content may move from candidate to canary and then to production.

This lifecycle is deliberately separate from agent update distribution. RulePack signing and release decisions live here; secure distribution and wire-side anti-downgrade enforcement are the responsibility of the fleet update path in #631.

## What a RulePack binds

A RulePack includes:

- a stable pack ID, explicit pack version, and canonical SHA-256 digest;
- typed `detection.Rule` definitions;
- the minimum agent version and accepted telemetry schema versions;
- required sensor versions and matcher fields;
- ATT&CK mappings;
- positive and negative replay fixtures;
- per-rule latency/CPU budgets;
- suppression policy, rollout cohorts, and rollback target.

Construction is fail-closed. Required fields must cover every field used by a rule matcher, ATT&CK mappings must point at rules in the pack, fixture expectations must name rules in the pack, positive fixtures must collectively exercise every rule, and each rule must have an explicit cost budget. Set-like inputs are canonicalized for the digest so declaration order does not create a different identity.

Version 1 uses rollback version `0` because no prior RulePack exists. Every later RulePack version must name an actual older version (`1..version-1`) as its rollback target. Deployment compatibility is checked against both the RulePack metadata and the telemetry reader in the running control-plane build. A deployment cannot claim a schema version that the current `telemetryschema` reader would reject. Forward admission also requires `previous_version` to equal the signed `rollback_version`, so canary/promotion cannot start with a broken rollback escape hatch.

## Trust model

RulePack signatures use Ed25519 over a domain-separated canonical RulePack encoding. The canonical digest is SHA-256 over that same normalized content; verification recomputes and validates the digest before verifying the signature. The signed artifact contains the key ID and signature, but it does **not** carry a public key that can declare itself trusted.

CI or an operator must supply the trusted RulePack Ed25519 public key separately. The CLI verifies that the supplied key has the expected fingerprint and that it verifies the exact canonical RulePack content. Mutating the pack after signing therefore fails digest validation and/or signature verification.

Release evidence has a separate trust boundary. Retro-hunt and purple rows are collected through `rulepack.EvidenceCollector`, which calls the existing telemetry `Hunt` and `purplecoverage.Service` seams and signs the resulting canonical evidence envelope under the domain-separated context `synapse-rulepack-gate-evidence:v1`. The envelope binds the exact RulePack identity, canonical gate input, and the bounded host/class/time-window/limit selectors used for every retro hunt. The gate CLI requires a separately supplied trusted evidence-producer public key. An evidence envelope cannot authorize its own embedded key, and raw `GateInput` JSON is not accepted by the CLI.

The public-key files used by the CLI are standard-base64 text for raw 32-byte Ed25519 public keys.

## CLI

All commands verify the RulePack signature against the externally pinned content key before doing any RulePack work.

```sh
synapse-cli rulepack verify \
  --artifact rulepack.signed.json \
  --public-key rulepack-release.pub
```

`verify` prints a small JSON identity record and exits non-zero if the pack, digest, key fingerprint, or signature is invalid.

```sh
synapse-cli rulepack replay \
  --artifact rulepack.signed.json \
  --public-key rulepack-release.pub
```

`replay` evaluates the pack's deterministic positive and negative fixtures. Positive fixtures collectively cover every rule and each fixture must fire exactly its declared rule IDs; negative fixtures must fire none. The JSON result is emitted even when a fixture fails so CI retains the evidence, and the command exits non-zero on any mismatch.

```sh
synapse-cli rulepack gate \
  --artifact rulepack.signed.json \
  --public-key rulepack-release.pub \
  --evidence rulepack-gate-evidence.json \
  --evidence-public-key rulepack-evidence.pub \
  --phase promotion
```

`gate` accepts `pre-canary`, `canary`, or `promotion` as the phase. The evidence file must be a `SignedGateEvidence` envelope produced by a trusted `EvidenceCollector`; the CLI recomputes its canonical evidence head, verifies the domain-separated attestation against the externally pinned evidence key, and then evaluates the embedded gate input. Phase checks are also bound to lifecycle state: `pre-canary` requires a candidate deployment, while `canary` and `promotion` require the deployment to already be in canary. This prevents a fully populated metrics object from bypassing the candidate → canary → promoted state machine. The command always emits the deterministic gate report after successful provenance verification and exits non-zero when the requested phase is not eligible.

The JSON decoder is strict: unknown fields, trailing JSON, malformed keys, and oversized inputs are rejected rather than ignored.

## Producing release evidence

`EvidenceCollector` is the trusted producer boundary for release evidence. A composition root or CI runner wires it with:

- the existing fleet telemetry service through the narrow `TelemetryHunter`/`Hunt` seam;
- the existing purple-coverage service through the narrow `PurpleReader`/`Trend` seam;
- the existing Ed25519 signer adapter configured with `GateEvidenceAttestationContext`.

The collection request carries deployment/policy/cost/quality measurements plus retro and purple selectors. It does **not** accept caller-supplied retro results or purple coverage rows. The collector obtains those two evidence classes from the authoritative services, validates the complete gate-input shape, and attests the exact pack identity, canonical input, and canonical retro-hunt selectors. The private evidence-signing key remains outside the domain/usecase layers.

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

Passing through the false-positive budget yields `pre_canary_passed`. Passing the canary stage yields `canary_passed`. Only a report with every required stage green has `passed=true` and may be used for promotion.

ATT&CK coverage is measured in basis points against every mapping claimed by the RulePack. Individual uncovered mappings remain visible in failure diagnostics, while the stage pass/fail decision follows the operator-owned `minimum_attack_coverage_bps` policy. A 90% policy therefore accepts 90% measured coverage; a 100% policy requires every mapping covered.

A failed release report never blocks rollback. Rollback still requires the RulePack's signed rollback metadata to identify the prior version correctly.

## Detection-quality metrics

Rates use integer basis points instead of floating point so CI decisions are reproducible. The report emits:

- precision and false-positive rate;
- reviewed-detection count and analyst disposition rate;
- suppression rate;
- detections per host-day (milli-detections);
- required-field capability availability across the declared evaluated field set;
- per-rule latency and CPU observations;
- measured ATT&CK coverage.

`required_field_availability_bps` currently means the fraction of the RulePack's required field kinds declared available by the evaluated sample/deployment, not per-event uptime. Per-event telemetry defects remain represented by the telemetry `DataQuality`/coverage model and can feed a richer availability aggregate when that measurement is added.

Canary and production stages re-enforce the precision/false-positive floors in addition to their host-day, detection-density, field-availability, suppression, and analyst-disposition requirements. A candidate cannot pass evaluation with good offline labels and then silently regress in production.

## Retro-hunt evidence

The existing telemetry service exposes both `Hunt` and `RetroRunRule`. RulePack release collection deliberately uses the lower-level `Hunt` seam and evaluates the **candidate RulePack rule** over the returned stored events.

That distinction matters: `RetroRunRule` uses the currently shipped detection catalogue, so using it directly to approve candidate content could test the old rule rather than the rule being promoted.

Each RulePack rule needs exactly one bounded retro case. A release window must contain context, must produce at least one candidate-rule match, and must be complete, unsampled, and free of recorded sequence gaps or losses. Each case also supplies an explicit event limit from 1 through 50,000; if the hunt returns exactly that many rows, the collector refuses the evidence because the telemetry port cannot prove there were no additional rows beyond the limit. Narrow the time window or use a larger still-bounded limit and collect again.

The signed evidence envelope retains the exact host, optional asset, event class, UTC time bounds, and row limit for every retro case. Those selectors are covered by the gate attestation, so changing the window after collection invalidates verification instead of leaving the same aggregate counts apparently authoritative.

## Purple/emulation evidence

Purple evidence is loaded through the existing `purplecoverage.Service` trend seam and bound to one explicit tenant/engagement/run/asset scope. A `covered` row is accepted only when its measured `Actual` detections contain the expected RulePack detection; a self-asserted verdict is not sufficient. Evidence for an unclaimed detection/taxonomy pair is rejected, and missing claimed mappings reduce measured ATT&CK coverage rather than being inferred as covered.

Release tooling should persist the signed gate-evidence envelope and emitted gate report beside the signed RulePack so a later review can reproduce why that exact digest was admitted, promoted, or rolled back.
