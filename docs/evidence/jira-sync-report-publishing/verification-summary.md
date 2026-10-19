# Verification summary

This summary distinguishes the current continuation checks from earlier full
suite results. Exact timestamps, exit codes, source input hashes, and output for
the current checks are recorded in
[`current-verification-checks.json`](current-verification-checks.json). The
The final worktree-bound Taurus report is written and validated before commit,
then refreshed for the committed HEAD before push. Its result is recorded locally
in `.git/taurus/verification.json`.

## Current continuation checks

The current selected input fingerprint in the check record is
`120a1ce6da8013742239ccb2dce43f5f7b0d0f0a48cb227aafd7389aa1e161bc` across
5,067 inputs. Passing commands recorded against that fingerprint:

| Check | Command | UTC | Result |
| --- | --- | --- | --- |
| Current baseline | `make lint build vet test typecheck` | 15:28:13–15:29:08, 18 Oct 2026 | Pass |
| Ticket race | `go test -race ./internal/usecase/ticketing ./internal/infrastructure/persistence/memory ./internal/adapter/httpapi -count=1` | 15:29:08–15:29:19, 18 Oct 2026 | Pass |
| Hostile tenant harness | `make harness` | 15:29:19–15:29:20, 18 Oct 2026 | Pass |
| Git acquisition regression | `go test -race ./internal/infrastructure/acquire -count=1` | Recorded in current check JSON | Pass; POSIX private Git clone scope |
| Automatic-admission stress | `go test -race ./internal/usecase/ticketing -run TestAutoPush -count=10` | Recorded in current check JSON | Pass; pending/refused/uncertain fence, 20 concurrent ticks, full 200-intent history and retry interval |

The recorded reconciliation output covers bounded request accounting,
fairness/checkpointing after timeout, provider state reconciliation and unreadable
ticket marking, and outbound work before the bounded inbound read. All four tests
pass; the exact output is also in
[`reconciliation-tests.txt`](reconciliation-tests.txt) for the #1436 PR excerpt.
The initial continuation baseline exposed a real private-clone regression; the
passing record follows its fix and is not an unchanged blind retry.

## Earlier full verification retained by scope

These checks cover unchanged persistence/migration and frontend surfaces. They
are not described as rerun during the current continuation.

| Check | Command | UTC | Result |
| --- | --- | --- | --- |
| Full Go suite with PostgreSQL | `go test -timeout 90m -p 1 -count=1 ./...` | 11:33:22–12:02:39, 18 Oct 2026 | Pass |
| Full frontend tests | `pnpm exec vitest run --maxWorkers=2` | 12:22:48–12:25:45, 18 Oct 2026 | Pass; 208 files / 1,408 tests |
| Frontend build | `pnpm build` | 12:25:45–12:25:47, 18 Oct 2026 | Pass |
| Affected sharing race tests | `go test -race ./internal/usecase/docpublish ./internal/composition ./internal/infrastructure/persistence/memory ./internal/infrastructure/integration/confluence -count=1` | 12:25:47–12:25:51, 18 Oct 2026 | Pass |
| Hostile tenant harness | `make harness` | 12:25:51–12:25:52, 18 Oct 2026 | Pass |
| PostgreSQL package repeat | `go test -timeout 90m -count=1 ./internal/infrastructure/persistence/postgres` | 12:26:28–12:53:23, 18 Oct 2026 | Pass |

The selected source fingerprint for that earlier review-remediation gate was
`7a79755dd200bbe1c3c33a277eeb1f587404f484de64c04c943a00e2d5b13729`. Persistence
and migration source did not change after the successful PostgreSQL runs; the
current continuation did not add frontend or persistence/migration source
changes. An intervening PostgreSQL repeat ended with `signal: killed` and exit 1;
it is not a passing run. The successful repeat used lower process concurrency and
a 1 GiB Go GC target against the same retained test database.

The earlier PostgreSQL suite for all packages took 1,472.376 seconds in its
PostgreSQL package. Existing database tests cover migrations 0242–0261, forced
RLS, protected rollback, repair, and tenant isolation. Production migration
capacity and production request latency are not measured by these local checks.

## Live acceptance evidence

Current real-provider evidence is summarized in [`README.md`](README.md) and
linked per fixture from [`visual-previews.md`](visual-previews.md). It includes
Cloud and licensed Jira Data Center lifecycle/native callback operations, real
Cloud polling and DC deletion, actual scheduled email receipts, and real
Confluence Cloud/Data Center pages. The current DC Confluence proof records the
scheduled page v4, legitimate build-provenance update to v5, unchanged-hash skip,
permission refusals, legal hold/release and governed purge. The current Cloud/DC
Project EN/VI issue captures and Jira DC policy EN/VI captures are present in the
image manifests. The current Jira DC linked-ticket console evidence is also
present and hash-verified: `SYNACC-3` is shown as new with a pending retest
proposal, Jira resolution context, and original/edited external comments. The
final PR body can use `Closes` for #1431, #1433, and #1435 once it attaches these
proofs and screenshots. The Project grouping scans used controlled Maven test manifests and produced an
actual Log4j scanner finding. Manually entered synthetic findings in the
Confluence report fixture are separate and are not represented as scan output.

## Review and CI scope

Current source review results and confidence limits are retained in
[`review-remediation-results.json`](review-remediation-results.json). Source
reviewers passed the recorded scopes; their results do not independently repeat
the private provider operations. GitHub Actions is disabled, so no hosted CI
result is claimed. Final combined implementation/acceptance QA passed after the linked-finding,
asset-table and provenance corrections. It independently checked all 71 manifest
files, 49 current images, 7 PDFs/7 pages, the 5,067-input source fingerprint and
41 recorded Done-action timestamps. Current admission/askpass QA, security,
performance, architecture and reliability reviews passed. The one optional low
performance finding is deferred: unmatched admission can load at most 200
payload snapshots; linked-ticket fast paths avoid that read, and no production
load claim is made.

Final artifact QA identified and corrected unsupported Project screenshot captions. Separate native DC EN/VI asset-table frames and Project console linked-key/state frames now carry those claims. PDF text verification also corrected the build-provenance note: initial/manual reports use VCS metadata, scheduled v4 used `devel`, and aligned v5 uses VCS metadata before the unchanged-content skip. These corrections changed evidence capture and captions; implementation code did not change.

Final public scan checked 179 files, including OCR, extracted PDF text and PR/comment drafts, against 34 known private credential candidates with zero matches. Fourteen root-owned private callback payloads were not readable for candidate extraction; no public file was skipped. The one discarded unauthenticated local readiness probe is separately disclosed in the Jira DC manifest and is not acceptance evidence.
