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

## Execution routes and identities

There are three closed routes.

| Route | When it applies | Analyzer and harness identity | Result use |
| --- | --- | --- | --- |
| Local diagnostic | No staged controller envelope is present. | Separate subject IDs; both commit and tree come from the local checkout. | Diagnostic only. A failed candidate ratchet is reported but does not make the command fail solely for that reason. |
| Protected baseline | A trusted controller stages the baseline envelope. | Fixed historical analyzer behavior is measured through reviewed behavior-neutral instrumentation; the harness records the actual reviewed checkout. | Creates or verifies controlled baseline evidence. |
| Candidate | A trusted controller stages the candidate envelope. | The analyzer and harness retain distinct subject IDs but must have the same independently derived checkout commit and tree. | Acceptance evidence. A rejected candidate returns a deterministic failure only after its validated sanitized publication is committed. |

The protected-baseline exception is intentional. It measures fixed historical analyzer behavior through reviewed behavior-neutral instrumentation; it does not run an executable built from the historical revision. The harness therefore preserves the actual reviewed checkout identity. A candidate executes the analyzer compiled from the exact checked-out source, so its analyzer revision must instead match that checkout exactly.

## Local prerequisites

A production run requires Linux on amd64. The trusted workflow also requires the Go version declared by `go.mod`, .NET SDK `8.0.100`, and the OpenJDK `java`, `javac`, and `jar` tools at `21.0.5`. Before the lifecycle starts, it builds `synapse-callgraph` and `synapse-ast` from the exact checkout into a private temporary tools directory and supplies them through `SYNAPSE_TAINT_CALLGRAPH_BIN` and `SYNAPSE_AST_BIN`.

The frozen production matrix requires these configuration points:

```text
SYNAPSE_JSREACH_TIER2_ENABLED=true
SYNAPSE_JVM_REACH_TIER2_POINTS_TO_ENABLED=true
```

Local runs are useful for diagnostic development, but only the trusted route can produce authoritative baseline or candidate evidence.

## GitHub routing and controller input

`.github/workflows/reachability-benchmark.yml` runs for pull requests to `main`, pushes to `main`, a nightly off-minute schedule, and manual dispatch without inputs. It derives one full lower-case source SHA from the event. Pull requests never use the self-hosted trusted runner.

For non-pull-request events, the route job permits trusted execution only when all reachability-specific repository settings agree exactly:

- `REACHABILITY_BENCHMARK_TRUSTED_ENABLED` is `true`.
- The event ref equals `REACHABILITY_BENCHMARK_TRUSTED_REF`.
- The event SHA equals `REACHABILITY_BENCHMARK_TRUSTED_SHA`.

It selects the protected-baseline route only when that selected SHA exactly equals `REACHABILITY_BENCHMARK_BASELINE_HARNESS_SHA`; every other selected SHA is a candidate route. Baseline routing and trust authorization are separate checks.

A trusted runner receives one externally managed source root through `REACHABILITY_BENCHMARK_CONTROLLER_ROOT`. The workflow derives the envelope name from the closed route and source SHA:

```text
baseline-<source-sha>.json
candidate-<source-sha>.json
```

It validates the external root, its `trusted-bundle/` directory, and the derived regular envelope for missing files, symlinks, and non-regular entries. It copies only the validated bundle and envelope beneath:

```text
$RUNNER_TEMP/synapse-reachability-controller/trusted-bundle/
$RUNNER_TEMP/synapse-reachability-controller/envelopes/
```

The benchmark receives the staged envelope through `SYNAPSE_REACHABILITY_CONTROLLER_ENVELOPE`; it does not receive controller source paths, identities, purposes, final modes, or run keys as operator inputs. The external controller root is never published.

The repository contains the canonical reviewed measurement inputs, baseline authority assets, candidate ratchet, and digest-bound bundle manifest under `internal/usecase/reachbench/trusted/`. The route envelope remains controller-owned and external: it must bind the selected source commit and tree to that reviewed bundle, and no placeholder envelope is checked in or accepted from operator input. A trusted route fails closed when the expected staged material is absent, stale, or invalid.

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
