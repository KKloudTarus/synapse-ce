# B07 verification summary

This summary records nine published source-check records
that completed successfully on 2026-10-17. It contains commands, exit outcomes,
and public test scope only.
Private provider credentials, endpoints, and raw runtime output remain outside the
repository.

| Check | Result | Evidence covered |
| --- | --- | --- |
| `make lint build vet test typecheck` | Passed, exit 0 at 16:08:33 UTC | Final Go lint, builds, tests, vet, and web TypeScript baseline. |
| `cd web && pnpm exec vitest run --maxWorkers=2 && pnpm build` | Passed, exit 0 | 208 test files and 1,400 tests; production web build. |
| `go test -race ./internal/infrastructure/acquire ./internal/usecase/sca ./internal/usecase/findings ./internal/usecase/projectuc ./internal/usecase/ticketing ./internal/usecase/docpublish ./internal/adapter/httpapi` | Passed, exit 0 | Race-sensitive acquisition, SCA, finding, Project, ticketing, document publication, and HTTP paths. |
| `go test ./internal/infrastructure/persistence/postgres -run 'Test(ScanJobStore.*ProjectAnalysis\|FindingRepositoryListFindingPage\|Ticket\|Document)' -count=1` | Passed, exit 0 | Fresh PostgreSQL Project analysis, finding-page, ticket, and document contracts. Generic-plan coverage and NULL-group coverage are distinct assertions within this run. |
| `go test -race ./internal/adapter/httpapi -run 'Test(Jira\|HostileHarness)' -count=1` | Passed, exit 0; repeated at 16:14:35 UTC | Final Jira/DC event-contract and hostile HTTP harness coverage. |
| `go test -race ./internal/usecase/ticketing ./internal/infrastructure/persistence/memory -run 'TestReceiveInboundWebhook(DeduplicatesProviderCommentAcrossJiraWebhookShapes\|CommentSnapshotsKeepProviderIdentityAndEdits\|NormalizesEmbeddedAndDedicatedCommentEdits)\|TestTicket' -count=1` | Passed, exit 0 | Final comment-delivery race coverage for cross-event dedupe and edited snapshots. |
| `go test -race ./internal/infrastructure/persistence/postgres -run '^TestTicketInboundReducerPostgresSerializesFindingProposalWindow$' -count=1` | Passed, exit 0 | Concurrent PostgreSQL inbound snapshot and proposal-window regression. |

| `cd web && pnpm exec vitest run src/pages/CodeQuality/ProjectSourceFindings.test.tsx --maxWorkers=2 && pnpm typecheck && pnpm build` | Passed, exit 0 at 16:15:05 UTC | Final icon convention alignment; 12 focused tests, TypeScript and production build. |

The final code and specialist review gates passed, including security's edit fix,
performance and reliability's narrow delta, the later Data Center metadata delta,
and implementation QA. The supplemental Source Findings icon-focused Vitest run
passed all 12 tests; TypeScript and the production build passed at 16:15:05 UTC.
The worktree-bound `.git/taurus/verification.json` is validated before commit and
refreshed for the committed tree before push; this summary does not replace it.

Live-provider evidence is recorded in the acceptance ledger and the public
[continuation provider proof](continuation-provider-proof.json),
[DC webhook proof](dc-webhook-provider-proof.json), and
[legal-hold proof](legal-hold-provider-proof.json). Known acceptance limits remain:
unassisted fresh group-only Confluence restriction creation and an opened final
Outlook PDF.
