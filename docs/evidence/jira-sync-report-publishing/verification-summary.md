# B07 verification summary

This summary records published command and provider evidence as of 2026-10-17.
It records public scope, timing and outcomes. Credentials, signing material and
raw runtime output remain outside the repository; the linked synthetic report
artifacts and provider captures are included for review.
It accompanies the worktree-bound Taurus gate and final review record.

| Check | Result | Evidence covered |
| --- | --- | --- |
| `make lint build vet test typecheck` | Passed, exit 0; 18:02:00–18:02:48 UTC | Current Go lint, builds, tests, vet, and web TypeScript baseline after the Documentation capability update. |
| `pnpm --dir web exec vitest run --maxWorkers=2` | Passed, exit 0; 18:18:36–18:21:39 UTC | 208 test files and 1,405 tests, including Documentation grouping, navigation, and delayed-identity read-only empty-editor tests. |
| `pnpm --dir web typecheck` | Passed, exit 0; 18:23:41–18:23:45 UTC | Current web TypeScript check after the read-only role guard. |
| `pnpm --dir web run build` | Passed, exit 0; 18:18:36–18:18:39 UTC | Production web build after the Documentation UI update and read-only role-state guard. |
| `go test -timeout 45m -count=1 ./internal/infrastructure/persistence/postgres` | Passed twice on the same clean PostgreSQL database, exit 0; 17:27:36–17:48:51 and 17:49:20–18:10:55 UTC | Full PostgreSQL persistence suite, including the fixture-cleanup regression. |
| `go test -race -count=1 ./internal/infrastructure/integration/confluence ./internal/usecase/docpublish` | Passed, exit 0 | Confluence restriction and governed document-publication paths. |
| `go test -v -count=1 ./internal/usecase/ticketing -run 'TestWorkflowTickReconcilesProviderStateAndMarksUnreadable\|TestInboundReconcileTimeoutCheckpointsAttemptedTargetForNextFairTick\|TestInboundReconcileChargesIdentityWithinReadBudget'` | Passed, exit 0 | Inbound Jira reconciliation fairness, timeout checkpointing, and unreadable provider state. |
| Earlier B07 focused race and PostgreSQL checks | Passed, exit 0 | Acquisition, SCA, finding, Project, ticketing, document publication, HTTP, inbound comment snapshot, and concurrent PostgreSQL proposal-window paths. The individual public records remain in `continuation-verification-checks.json`. |

The final Tier 0 architecture/QA/security panel and required specialist reviews
passed with no open findings. The readonly UI and fresh licensed Jira findings
were resolved with regression tests and live proof. The public
[final review record](final-review-results.json) preserves reviewer scope and
limitations; the current worktree-bound `.git/taurus/verification.json` is validated
before commit/push. GitHub Actions are disabled for this repository, so no hosted-CI result is
claimed. A frontend role-state guard was added after review identified a newly
reachable read-only empty-editor path; its three regression cases failed before the fix, then both focused suites passed
(37 tests). The complete UI suite and production build passed after the fix.
Real configured, empty, delayed-response loading, upstream-502, and read-only empty
journeys were inspected in Edge; the isolated fixture was restored after capture.
See [Documentation proof](documentation-discovery-proof.json).

Live provider proof includes automatic group-only restriction creation before
content upload for Confluence Cloud page `131374` and fresh Confluence Data Center
page `327686`: each completed create in one attempt, a republish reached version 3,
the scheduled run reached version 4, and governed purge returned the current page,
history, trash, and report attachments as absent. See the public
[Cloud proof](automatic-cloud-provider-proof.json) and
[Data Center proof](automatic-dc-provider-proof.json). The scheduled PDF email
proof records receipt by both approved personal mailboxes and a two-page native
Gmail PDF view. Outlook received the same attachment, but its native preview
reported a client-side preview error; that limitation is recorded without treating
it as an attachment-delivery failure. See the
[scheduled email proof](scheduled-email-provider-proof.json).

Fresh Jira DC acceptance used normal Synapse API/worker creation of restricted
`SYNACC-1` followed by an independent reviewer's genuine native callbacks. Seven
valid HMAC forwards returned 202 at 18:39:28–18:40:36 UTC, before the official
three-hour test license expired at 20:54:31. Final readback retained one pending
proposal, a confirmed finding and two distinct snapshots for one remote comment.
The native registration, proxy and temporary route were closed. The older expired-lab
callback record is historical only. See [fresh Jira proof](fresh-jira-native-provider-proof.json).
