# Reachability benchmark runbook

The reachability benchmark is a fixed production-lifecycle measurement, not a general-purpose comparison command. Run it locally with no arguments:

```bash
make reachability-benchmark
```

The command derives checkout identity, run identity, route, and output locations itself. Do not provide a SHA, run key, controller path, purpose, or final mode. Those values are deliberately not command-line inputs.

## What the lifecycle measures

The shared `benchcycle` foundation provides the operational mechanics: an isolated workspace, two bounded capture passes, semantic-repeat comparison, private evidence retention, staged sanitized publication, cleanup, and replay before the staged publication is committed. Reachability supplies the domain semantics on top of that foundation: the frozen corpus and production bindings, outcome and coverage calculations, suppression safety, baseline checkpoints, and candidate ratchets.

The frozen production matrix has **83 logical cases**, **95 execution cells**, and **190 captures**: every cell is captured twice. An unavailable or incomplete analysis is recorded as its actual outcome and coverage state; it is never substituted for a successful reachability result.

The report evaluates three independent axes:

- **Outcome:** reachable, conditionally reachable, present but unreached, or no analysis.
- **Coverage:** whether the required execution was observed completely, partially, or not at all.
- **Suppression safety:** whether a suppression was justified, complete, and safe. Unsafe or incomplete suppression evidence cannot be hidden by outcome scores.

Read candidate results as a ratchet decision, not a single headline score. The candidate must make strict C2 progress while preserving non-offsettable recall, coverage, and suppression safeguards. The sanitized report carries the evaluated acceptance state and its reasons.

Candidate and local-diagnostic runs also execute a separate suppression-projection conformance sidecar for exactly four frozen controls: Go source Tier-2, Python import, Python semantic, and .NET build-aware import. The sidecar reuses each control's actual normalized analyzer result and subjects in an isolated normal production coordinator, then verifies that the persisted judgment projects through `export.DeriveReachabilityEvidence` as `present_unreached`. Its two digest-bound reports participate in semantic repeat and staged replay. This does not change `MeasuredObservation.Suppression`, which remains `none`, and it does not claim a downstream VEX result, SLA change, promotion, attack-path exclusion, report hiding, or deployment-completeness proof.

## Execution routes and identities

There are three closed routes.

| Route | When it applies | Analyzer and harness identity | Result use |
| --- | --- | --- | --- |
| Local diagnostic | No staged controller envelope is present. | Separate subject IDs; both commit and tree come from the local checkout. | Diagnostic only. A rejected candidate still returns the deterministic candidate-rejection error after its sanitized publication commits; it is not acceptance evidence. |
| Protected baseline | A trusted controller stages the baseline envelope. | Fixed historical analyzer behavior is measured through reviewed behavior-neutral instrumentation; the harness records the actual reviewed checkout. | Creates or verifies controlled baseline evidence. |
| Candidate | A trusted controller stages the candidate envelope. | The analyzer and harness retain distinct subject IDs but must have the same independently derived checkout commit and tree. | Acceptance evidence. A rejected candidate returns a deterministic failure only after its validated sanitized publication is committed. |

The protected-baseline exception is intentional. It measures fixed historical analyzer behavior through reviewed behavior-neutral instrumentation; it does not run an executable built from the historical revision. The harness therefore preserves the actual reviewed checkout identity. A candidate executes the analyzer compiled from the exact checked-out source, so its analyzer revision must instead match that checkout exactly.

## Local prerequisites

A production run requires Linux on amd64; the lifecycle continues to reject every other platform. It requires the Go version declared by `go.mod`, .NET SDK `8.0.100`, and the OpenJDK `java`, `javac`, and `jar` tools at `21.0.5`.

`make reachability-benchmark` supplies missing helper binaries automatically. It preserves non-empty `SYNAPSE_TAINT_CALLGRAPH_BIN` and `SYNAPSE_AST_BIN` values, so trusted runners can provide their prebuilt helpers. For each unset path, the target builds the matching helper from the current checkout into a private temporary directory, exports that path only for the lifecycle, and removes the directory at shell exit. It does not write helpers into the checkout.

The target also freezes `SYNAPSE_JSREACH_TIER2_ENABLED=true` and `SYNAPSE_JVM_REACH_TIER2_POINTS_TO_ENABLED=true`, so a no-argument local diagnostic uses the same production matrix as the trusted workflow without manual configuration. The workflow therefore only supplies its prebuilt helper paths; it does not configure those feature flags separately.

Local runs are useful for diagnostic development and require no review trust material. An authoritative baseline or candidate route additionally requires externally provisioned detached-review trust and signatures; a controller envelope alone is never authority.

## GitHub routing and controller input

`.github/workflows/reachability-benchmark.yml` runs for pull requests to `main`, pushes to `main`, a nightly off-minute schedule, and manual dispatch without inputs. It derives one full lower-case source SHA from the event. Pull requests never use the self-hosted trusted runner. Current pre-merge runs remain diagnostic: this repository has no independent pre-merge workflow verifier or bootstrapped workflow trust root. This change does not alter that workflow or claim otherwise.

For non-pull-request events, the route job permits trusted execution only when all reachability-specific repository settings agree exactly:

- `REACHABILITY_BENCHMARK_TRUSTED_ENABLED` is `true`.
- The event ref equals `REACHABILITY_BENCHMARK_TRUSTED_REF`.
- There is no reachability trusted-SHA variable; `REACHABILITY_BENCHMARK_TRUSTED_SHA` is forbidden.

It selects the protected-baseline route only when that selected SHA exactly equals `REACHABILITY_BENCHMARK_BASELINE_HARNESS_SHA`; every other selected SHA is a candidate route. Baseline routing and trust authorization are separate checks.

A trusted runner receives one externally managed source root through `REACHABILITY_BENCHMARK_CONTROLLER_ROOT`. The workflow derives the envelope name from the closed route and source SHA:

```text
baseline-<source-sha>.json
candidate-<source-sha>.json
```

It validates the external root, its `trusted-bundle/` directory, the derived regular envelope, and a closed route-specific `authority/` inventory. Every staged authority entry must be an ordinary, non-symlink file below the external controller root, must fit the JSON size bound, and must appear exactly once in the route inventory; missing, extra, escaped, reparse, or private-key entries fail closed. It copies only the validated bundle, envelope, and authority files beneath:

```text
$RUNNER_TEMP/synapse-reachability-controller/trusted-bundle/
$RUNNER_TEMP/synapse-reachability-controller/envelopes/
$RUNNER_TEMP/synapse-reachability-controller/authority/
```

The benchmark receives the staged envelope through `SYNAPSE_REACHABILITY_CONTROLLER_ENVELOPE`; it does not receive controller source paths, identities, purposes, final modes, or run keys as operator inputs. The external controller root is never published.

### Curating controller authority

Use the separate curator only to construct controller material after reviewed evidence exists. It derives source identity from the current checkout; it never accepts a SHA, tree, run key, corpus, oracle, purpose, or final mode.

```bash
go run ./cmd/synapse-reachability-authority prepare-baseline \
  /secure/reviewed-baseline-evidence.json /secure/baseline-authority
```

The output directory must not exist; its real parent must already exist, and the destination must be outside the inspected checkout. The command requires a pristine non-shallow checkout with the fixed baseline revision in its ancestry. It validates, references, and stages the supplied canonical review document, then atomically installs an unsigned controller containing `trusted-bundle/`, `authority/baseline-review-evidence.json`, and `envelopes/baseline-<head>.json` without replacing an existing destination. It does not create approval or a signature.

After a protected-baseline lifecycle has published its sanitized leaf, derive the commit-ready candidate authority from that publication and the generated baseline-authority root:

```bash
go run ./cmd/synapse-reachability-authority derive-candidate \
  /secure/published-baseline /secure/baseline-authority \
  /secure/reviewed-candidate-evidence.json /secure/reviewed-disposition-evidence.json \
  /secure/candidate-authority
```

The curator replays the sanitized publication, validates the original allowlist, and atomically installs only the candidate authority files intended for the checked-in trusted root. Those files include the trusted bundle, baseline lifecycle material, canonical review and disposition evidence copies, and `authority/candidate-assets-provenance.json`. It writes no candidate envelope, signature, trust policy, or private key; its provenance has no envelope reference. Review and disposition actor text is descriptive only. Each curator destination must not already exist.

Install those files at `internal/usecase/reachbench/trusted` in the final checkout and commit them. From that final pristine checkout, create the separately staged controller material:

```bash
go run ./cmd/synapse-reachability-authority prepare-candidate \
  /secure/candidate-controller
```

`prepare-candidate` accepts no authority-source path. It reads only ordinary `100644` blobs at the fixed `internal/usecase/reachbench/trusted` path in the captured final commit tree, rejects altered index state, replacement refs, and legacy graft files, then revalidates the pristine commit and tree immediately before atomically installing the output. It reconstructs those committed bytes beneath `trusted-bundle/`, stages canonical baseline review and disposition documents, and adds `authority/candidate-review-subject.json` plus `envelopes/candidate-<final-head>.json`. The candidate-review subject binds the repository identity, final harness commit/tree, fixed authority path, committed blob inventory digest, baseline evidence references, bundle, snapshot, and candidate-acceptance approval semantics. It deliberately has no envelope reference. The output is unsigned and non-authoritative until an external process provisions the trust policy and detached signatures; do not commit or publish that external controller material.

### External detached review trust

The controller root receives its trust root only from an external provisioning process. It must contain canonical `authority/review-trust.json`, which maps three distinct bounded principal and key IDs to full Ed25519 public keys, matching SHA-256 fingerprints, and the `baseline_reviewer`, `baseline_maintainer`, and `candidate_reviewer` roles. It is never derived from an environment key, a candidate bundle, or a curator command.

The same external process supplies canonical sidecars containing only a key ID and detached Ed25519 signature at these fixed paths:

```text
authority/baseline-review-evidence.signature.json
authority/baseline-disposition-evidence.signature.json
authority/candidate-review-subject.signature.json
```

The trusted baseline route stages exactly `review-trust.json`, `baseline-review-evidence.json`, and `baseline-review-evidence.signature.json`. The candidate route stages those three files plus `baseline-disposition-evidence.json`, `baseline-disposition-evidence.signature.json`, `candidate-review-subject.json`, and `candidate-review-subject.signature.json`. No route stages a private key. The runner verifies domain-separated signatures over the original canonical documents. A protected baseline requires the authenticated baseline review. A candidate also requires an authenticated baseline disposition from a distinct maintainer and an authenticated exact-candidate review subject; the three roles require distinct principal IDs, key IDs, fingerprints, and public keys. Missing, stale, malformed, foreign, cross-context, reused-key, or self-supplied material fails closed. No private-key loader, signer command, public-key fixture, repository secret, or independent pre-merge trust root is introduced here.

The repository stores only the curator-derived, commit-ready trusted inputs and baseline authority assets under `internal/usecase/reachbench/trusted/`. Route envelopes, the review trust policy, detached signatures, and all private keys remain controller-owned and external. A trusted route fails closed when either the committed authority assets or the expected staged controller material is absent, stale, or invalid.

## Baseline and candidate lifecycle

A protected baseline records a reviewed baseline checkpoint from the fixed analyzer and the selected harness procedure. The checkpoint supplies the policy, corpus, inventory, oracle, coverage, and suppression constraints from which a candidate ratchet is derived.

A candidate uses that independently checkpointed baseline. It must improve the ordered C2 vector and must not regress mandatory reachability, coverage, or suppression conditions. A rejection preserves the sanitized report and its rejection reasons, then fails the authoritative candidate command. Do not lower a ratchet or alter a checkpoint simply to turn a candidate green; capture the evidence, correct the analyzer or contract, and perform a new reviewed checkpoint when the baseline itself must change.

## Publication, retention, and cleanup

Raw capture evidence stays in the restricted private workspace. The lifecycle publishes only digest-bound sanitized artifacts after its stage-only replay recomputes and verifies the staged report. The workflow aggregates job status and sanitized-artifact presence; it does not independently parse report JSON.

The fixed temporary locations are:

```text
$RUNNER_TEMP/synapse-reachability/private/
$RUNNER_TEMP/synapse-reachability/published/github-<run-id>/attempt-<attempt>/
$RUNNER_TEMP/synapse-reachability-tools/
$RUNNER_TEMP/synapse-reachability-controller/
```

The workflow uploads only the sanitized published leaf, with short retention. Its upload step still runs after a rejected candidate so published rejection evidence is retained when publication completed. It then removes the staged controller copy, private tools, restricted evidence workspace, and published workspace. Never upload the controller root or restricted raw evidence as a workflow artifact.

## Operating responsibility

The repository owner responsible for the protected benchmark configuration enables or disables trusted execution by managing the reachability-specific repository settings and the external controller material. Keep it disabled when the fixed runner, exact ref/SHA authorization, toolchain, controller bundle, or checkpoint cannot be verified. An untrusted event is intentionally skipped by the trusted job; the aggregate verifies that skip rather than treating it as a benchmark result.

When a trusted run fails, first determine whether it failed before publication, during deterministic replay, or after candidate rejection. A candidate-rejected job with a retained sanitized artifact is an evidence-bearing rejection, not a missing measurement. Missing controller material, an identity mismatch, a symlink, a non-regular staged input, or an absent artifact is a fail-closed operational error and must be repaired at the controller or trusted-runner boundary rather than bypassed with manual inputs.
