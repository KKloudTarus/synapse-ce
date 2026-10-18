# Review-remediation verification

This supersedes earlier current-baseline claims. The [17 October snapshot](verification-2026-10-17.md) remains historical. [Command evidence](review-verification-checks.json) records commands, UTC timestamps, exit codes and selected source fingerprints before/after each check. Commit dates are not used to infer source-edit times.

| Check | Command | UTC start → finish | Result |
| --- | --- | --- | --- |
| postgres-full-first | `go test -timeout 90m -p 1 -count=1 ./...` | 2026-10-18T11:33:22.125681+00:00 → 2026-10-18T12:02:39.691940+00:00 | Pass |
| final-baseline | `make lint build vet test typecheck` | 2026-10-18T12:22:02.539823+00:00 → 2026-10-18T12:22:48.077823+00:00 | Pass |
| final-web-full | `pnpm exec vitest run --maxWorkers=2` | 2026-10-18T12:22:48.078152+00:00 → 2026-10-18T12:25:45.098428+00:00 | Pass |
| final-web-build | `pnpm build` | 2026-10-18T12:25:45.098650+00:00 → 2026-10-18T12:25:47.364666+00:00 | Pass |
| final-sharing-race | `go test -race ./internal/usecase/docpublish ./internal/composition ./internal/infrastructure/persistence/memory ./internal/infrastructure/integration/confluence -count=1` | 2026-10-18T12:25:47.364846+00:00 → 2026-10-18T12:25:51.152360+00:00 | Pass |
| final-hostile-harness | `make harness` | 2026-10-18T12:25:51.152571+00:00 → 2026-10-18T12:25:52.505113+00:00 | Pass |
| postgres-repeat-current | `go test -timeout 90m -count=1 ./internal/infrastructure/persistence/postgres` | 2026-10-18T12:26:28.470675+00:00 → 2026-10-18T12:53:23.168429+00:00 | Pass |

The final selected-source fingerprint is `7a79755dd200bbe1c3c33a277eeb1f587404f484de64c04c943a00e2d5b13729`. It covers Go/SQL, web source and selected build inputs; documentation/evidence are excluded. The Taurus gate separately binds the entire Git worktree. Full frontend passed 208 files / 1408 tests. Inputs did not change during the final baseline, frontend/build, affected race/harness checks or current PostgreSQL repeat.

The earlier all-package PostgreSQL pass used `fdfee4b3ca346b6937f6ea7ede3bacdea2ca54daa9cc264f820dc33380d2f1df`; its PostgreSQL package took 1472.376 s. Persistence and migration source remained unchanged thereafter. Vendor-schema decoding and monitor/tenant budgets were then corrected after live Cloud reads exposed defects. The final baseline, affected tests and current PostgreSQL repeat exercise that final source. Both successful database passes used the same isolated `review_final` database, without an operator reset between attempts. Fixtures retain their normal schema-reset and cleanup behavior.

One intervening repeat ended with `signal: killed`, exit 1, without an assertion failure in its terminal log. That log does not establish its cause. It is not a pass; it also compiled an earlier snapshot while later policy/monitor edits were made. The successful retry used a 1 GiB Go GC target and fewer concurrent processes, with the same database and unchanged assertions. Initial resource-unbounded lint/build attempts were also killed; one baseline found an unset Helm shim. Passing commands use the installed pinned Go/Helm/lint/Node/pnpm paths.

Behavioral regressions cover shared status refusals, monotonic deletion, explicit refused-field retry, template secrets, strict vendor policy shapes, actual Router tenant/egress denial, monitor claim/timeout/configuration/CAS behavior, forced RLS and migrations 0242–0261 round trips/protected rollback/repair. Tier 0 QA/security/performance/architecture/reliability/platform/frontend reviews passed their source scopes. Final combined QA, security and performance followup inspected the policy/monitor correction and current logs; [review scope](review-remediation-results.json) is explicit.

[Current Cloud proof](review-cloud-provider-proof.json) covers create/update/hash-skip, real calendar version 4, three PDF attachment downloads and authenticated purge readbacks. [Monitor proof](review-provider-availability.json) records successful refreshed connections and the configured-group mismatch warning. Missing DC/native callbacks/multi-asset producer/mail reruns keep all eight issues at `Refs`. Historical captures and mocks do not establish those reruns. Actions is disabled; no hosted-CI pass is claimed.

CI YAML parsed with a finite 240-minute backend job and 90-minute test budget. `make -n GO_TEST_TIMEOUT=7m test` propagated the override. The production migration deadline remains two minutes. Prose publishing-policy validation and the local known-credential scan pass; the latter includes raw changed files, extracted PDF text and the assembled PR body/comment.
