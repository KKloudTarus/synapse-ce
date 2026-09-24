# Benchmark acceptance and retirement

This runbook closes the benchmark work for an exact commit on `main`. It records evidence for the seven
benchmark workflows without treating a green aggregate as proof that its underlying measurement ran.

## Select the acceptance subject

1. Merge the intended changes to `main`, then record its full lower-case 40-character SHA as
   `ACCEPTANCE_SHA`. Do not accept results from a pull-request merge ref, a later `main` SHA, or a manually
   selected branch that does not resolve to `ACCEPTANCE_SHA`.
2. Dispatch every workflow from `main` at that SHA: `engine-accuracy.yml`,
   `reachability-benchmark.yml`, `security-accuracy.yml`, `dynamic-security-benchmark.yml`,
   `performance-benchmark.yml`, `sast-benchmark.yml`, and `owned-default-readiness.yml`.
3. Preserve each run URL, workflow run ID and attempt, event, source SHA, aggregate job URL and conclusion.
   For the hosted security, dynamic, performance, and SAST lanes, the route job, checkout assertion, and
   aggregate must all succeed for `ACCEPTANCE_SHA`.

## Collect non-vacuous evidence

For every run, retain the aggregate log and the logs for every benchmark job. A passing aggregate is valid
only when all required jobs ran successfully and the workflow's required artifacts are present; a skipped
trusted job is authorization evidence only, not an accepted measurement.

| Workflow | Evidence required for acceptance |
| --- | --- |
| `engine-accuracy.yml` | Trusted route is `true`; trusted benchmark job ran; sanitized result artifact is present; its revision equals `ACCEPTANCE_SHA`. |
| `reachability-benchmark.yml` | Trusted route is `true`; trusted benchmark job ran; controller review and disposition evidence bind the source; sanitized artifact is present. |
| `security-accuracy.yml` | Route, exact checkout assertion, accuracy job, and aggregate succeeded for `ACCEPTANCE_SHA`. |
| `dynamic-security-benchmark.yml` | Route, exact checkout assertion, accuracy job, and aggregate succeeded for `ACCEPTANCE_SHA`. |
| `performance-benchmark.yml` | Route, exact checkout assertion, measurement job, aggregate, and SHA-named performance-baselines artifact succeeded. |
| `sast-benchmark.yml` | Route, exact checkout assertions, all scorecard jobs, aggregate, and SHA-named artifacts succeeded. OWASP, Juliet, Securibench, and pinned Semgrep evidence is present; the Python and sanitizer adversarial gates passed; post-triage precision improved over an accepted committed baseline without losing a true case or breaching a recall floor. |
| `owned-default-readiness.yml` | Route and readiness job succeeded; download `readiness.txt` and verify `revision: ACCEPTANCE_SHA` and `evidence_current: true`. |

An ordinary green readiness aggregate does not establish currency: it may be for a revision that is not the
designated candidate. The final acceptance artifact for `ACCEPTANCE_SHA` must explicitly contain
`evidence_current: true`.

The SAST route runs three propose-stage corpora, the pinned Semgrep comparison, and Python and sanitizer
adversarial regressions. Its green aggregate does not satisfy the SAST row until an accepted post-triage
improvement gate has been added and passed on `ACCEPTANCE_SHA`. The committed pre-tuning diagnostic control
is not an accepted baseline.

Record each downloaded artifact's GitHub artifact ID, SHA-256 digest, retention period, and storage location.
Record a short independent review of the collected evidence and its disposition. The reviewer must not be the
person who prepared the trusted input or accepted the benchmark claim. For engine accuracy, retain the
independent pull-request review and a maintainer disposition from a different identity that bind the exact
implementation commit; for reachability, retain the controller's corresponding review and disposition
evidence. An accepted capture must be promoted before removing the owned-default evidence-debt marker.

## Retire the temporary required checks

Do this only after the independent reviewer accepts the complete evidence set and records any finding as
fixed, deferred with an owner and date, or rejected with a reason. Capture the repository branch-protection
and ruleset configuration before changing it. Remove only required checks belonging to these workflows:
`Aggregate benchmark status` for engine and reachability, `Aggregate security accuracy status`, `Aggregate
dynamic benchmark status`, `Aggregate performance status`, `Aggregate readiness status`, and `Aggregate SAST
benchmark status` (or the prior SAST scorecard checks if branch protection still lists them). Preserve all
unrelated protection and deployment checks.

Disable the seven workflows through the GitHub Actions API with the `disabled_manually` state. Record the
API response for each workflow, then read each workflow back and verify its state is exactly
`disabled_manually`. Confirm a new push to `main` produces no run for any disabled workflow. Keep the
acceptance evidence and configuration before/after snapshots with the final EPIC disposition.

## Re-enable

Re-enable a retired workflow only through a reviewed repository configuration change or an authorized
maintainer action. Restore its required-check entry only after a fresh exact-SHA run has passed with the
evidence required above.
