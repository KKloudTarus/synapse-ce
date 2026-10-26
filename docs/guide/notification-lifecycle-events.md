# Lifecycle notification delivery

The remaining lifecycle events extend the existing version-3 capture and delivery
framework. They preserve tenant boundaries, historical display facts and canonical
recipient identities without introducing another queue or transport registry.

## Design constraints

- Engagement creation and transitions capture facts inside the business transaction.
  Source-upload preparation runs before that transaction; metadata binding and capture
  commit together. Unknown commit outcomes retain prepared bytes for recovery.
- Window identities contain the selected UTC boundary and lead time. A bounded,
  restartable poller treats start and end categories independently and checks relevance
  again before sending. DST display offsets do not change instant identity.
- Comments retain a bounded excerpt; mentions use explicit validated canonical IDs,
  an immutable tenant-owned relation and personal-only fanout.
- Approval capture follows the stored canonical proposal and decision on retries.
  Reviewer membership is immutable per source, with status and review permission
  rechecked at delivery. Decisions remain governed console actions.
- Incident changes and response outcomes append their outbox facts at the authoritative
  state commit. Ambiguous execution, verification and halt observations retain their
  audit records without claiming a finished outcome. External response execution never
  runs inside that short transaction.
- Evidence verification remains fail closed. Its append-only custody alert commits
  independently of report rollback; delivery failure cannot make the chain reportable.
  If notification facts or outbox capture fail, a separate audit attempt preserves the
  custody signal. Retries retain the first observation timestamp and hash; different
  immutable audit content is rejected.
- Public event data stays bounded and scrubbed. Rendering uses captured display facts;
  current user state is consulted only to authorize delivery.
- Migration is additive. Upgrade notification workers before enabling new API
  producers; schema compatibility alone does not make old consumers compatible.

## Rollout and recovery

Migration 238 follows the shipped ticketing migration 237. The earlier local
reservation 236 was never shipped by this change. Upgrade from the current main
schema before enabling these producers; do not renumber already applied sandbox
history or load duplicate Goose versions. Historical sandbox captures retain their
original schema provenance, while migration checks exercise the current sequence.

Apply migration 238 before starting binaries. Replace or drain every old notification
worker, start workers that recognize the new event types, then enable the API producers.
Monitor source-poll failures, oldest pending source age and delivery dead letters.
An old worker rejects these event types and rolls back the whole tenant projection
transaction, which can also delay older notifications. See
[notification content capture](notification-content.md) for the projection failure contract.

For a binary rollback, retain migration 238 and keep capable notification workers until
new sources and deliveries have drained. Downgrade the API first to stop new production.
If capable workers cannot remain, preserve the queue and forward-fix before resuming
projection. Schema Down refuses durable mentions, approval rosters, recipient-role
facts, role rules and pending lifecycle work. It locks guarded tables before checking
so a concurrent committed fact cannot escape the refusal guard. Do not delete or
retarget immutable records to make rollback succeed.

Choose the PostgreSQL runtime role before recording custody observations. Production
requires RLS from the first write. The current API and worker reject roles that
bypass RLS at startup. Historical databases or test harnesses that write through
such a role use a global v1 audit chain; a restricted runtime role writes tenant
v2 chains. Switching
an existing database between these modes is unsupported. In particular, after a
dev-to-runtime switch, RLS hides a prior v1 observation while its unique key still
blocks a duplicate v2 insert. The original audit remains, but the repeated custody
notification cannot commit. For production, provision a separate database with the
restricted runtime role and retain the development database as historical evidence.
Do not rewrite audit rows or treat a duplicate-key error as successful verification
without comparing the stored immutable payload.

Roster correctness is verified through 1,000 approvers. The insertion guard counts the
existing roster per inserted row; benchmark isolated capture and concurrent requests
before claiming a larger operating envelope. The current tests establish correctness,
not a production latency SLO.

## Scope and acceptance

The implementation covers #1408, #1409, #1394, #1395 and #1404–#1407, reuses the
merged #1415 recipient-role framework, and excludes #1410, owned by nnatuan03.
The maintainer explicitly deferred SMTP, Teams and PagerDuty client evidence to
[#1576](https://github.com/KKloudTarus/synapse-ce/issues/1576) on 2026-10-14.
Historical evidence for earlier event types does not certify these new event cells.

| Assigned leaf | Event coverage | Acceptance boundary |
| --- | --- | --- |
| #1408 | `engagement.created`, `engagement.status_changed` | Transactional captured facts, rollback/restart and native shared-client matrices |
| #1409 | `engagement.window_starting`, `engagement.window_ending` | Durable UTC identity, DST display, independent categories, concurrent poll dedupe and current relevance |
| #1394 | `finding.commented` | Comment/outbox atomicity, bounded historical excerpt and shared-client matrices |
| #1395 | `finding.mentioned` | Explicit canonical identities, tenant/active/permission checks, immutable personal recipients and verified Slack DM/inbox evidence; excluded from shared matrices |
| #1404 | `approval.requested`, `approval.decided`, `approval.timed_out` | Canonical retry identity, immutable reviewer snapshot and delivery-time authorization; decisions remain console actions |
| #1405 | `incident.updated` | Authoritative incident mutation and outbox commit together; real service and native delivery evidence |
| #1406 | `response.finished` | Transactional bounded outcomes and crash/idempotency tests; provider evidence uses synthetic facts, with no remote execution claim |
| #1407 | `evidence.chain_broken` | Independent append-only alert transaction, mandatory floor and fail-closed reporting tests; provider evidence uses synthetic facts, with no live tampering claim |
| #1410 | `report.generated` | Capture keyed by the sealed report digest, so a rebuild and a later release announce once; `go test ./test/notifylive` posts it to every configured client through the shipped template and formatter, and the payload half runs with no destination |

The local test environment uses PostgreSQL 17 and the existing dedicated notification
workspaces. The candidate API, notification worker and built web console bind to
loopback ports 18086, 19096 and 15174. The original API/web and the parallel Jira
workstream remain available. Credentials and repeatable operation state stay in the
operator's private runtime directory.

Native HTTP operations created and activated an engagement, then added a comment
with an explicit canonical mention. A private helper invoked the real approval and
incident services against those dedicated entities. `response.finished` and
`evidence.chain_broken` client posts use explicitly labelled synthetic fixtures;
they do not prove remote response execution or a live custody failure.

Before projection, the worker was stopped and eleven scoped sources committed.
The API was killed after commit, then API and worker restarted. Window scheduling
supplied the two additional boundary sources. Correlated receipts and client views
must retain this distinction between source operations, fixtures and provider acceptance.

## Verification ledger

| Check | Current evidence |
| --- | --- |
| Frontend baseline | Node 22, pnpm 9.15.9: 189 files / 1,273 tests passed |
| Frontend after review fixes | 12 focused tests passed, including reordered GET and failed refresh; `tsc -b` and Vite build passed |
| PostgreSQL producers and isolation | Full current PostgreSQL package passed with `-parallel 1`, 2,097.792 seconds; lifecycle, UTC/DST windows, restart/concurrency, hostile tenants and immutable role snapshots included |
| Approval capacity | 51 and 1,000 captured recipients, replay, rollback and revocation passed; this is correctness evidence |
| Review regressions | One concurrent requested audit, one-connection projection and migration Down concurrent-commit refusal passed in a real PostgreSQL run |
| Mention picker | Both real PostgreSQL picker tests passed; readonly/integration_admin included only for mention purpose |
| Historical Go baseline | Full Linux and Windows CI-shaped suites passed after reconciliation with main `18186516`. Windows used Git Bash, `GOMAXPROCS=2` and `TMP=TEMP=C:\Temp`; current logs are `linux-main-reconciled-full.log` and `windows-main-reconciled-full.log`, with separate actual-exit receipts. Earlier failed invocations remain failed evidence. |
| Historical checks | The main `18186516` all-command build/vet and lint passed. Lint used `--allow-serial-runners` after another live lint process held the lock; the initial refused invocation remains separate failed evidence. Five affected packages/race, schemas/docs and real PostgreSQL mention regression passed. That Linux container-filesystem suite passed (`go test -p 1 -timeout 60m ./...`, non-root, CGO disabled; `linux-main-reconciled-full.log`). |
| Native views | Slack, JSM, Mattermost, Rocket.Chat, Discord, Telegram, Google Chat and webhook each have 88 individually reviewed event/locale/class/theme cells and six clicked source-event destination groups. Console state and personal Slack mention evidence are recorded separately. |

The optional broad PostgreSQL baseline run encountered stale source/approval fixtures and
migration-cleanup timeouts under contention. The fixtures were corrected to match current
contracts; every failed test was rerun successfully in focused real PostgreSQL checks.
That earlier broad invocation is retained as failed evidence. A new full PostgreSQL package run
against the isolated test database completed successfully after the corrections: `go test -p 1
-parallel 1 -timeout 90m -count=1 ./internal/infrastructure/persistence/postgres`, exit 0.
The earlier verification snapshot covered 4,091 Go, SQL and module files on main
`18186516`, with only CRLF/LF differences for the then-unshipped migration 236.
Those receipts remain historical evidence. Current verification receipts are bound
to the reconciled worktree in its verification report. The current candidate follows main
`43e5fea2`, including the shipped ticketing migration 237; its unshipped lifecycle
migration is 238. Applied sandbox histories remain unchanged.

Earlier Windows baselines failed the runtime-cap test, Unix-socket broker tests,
filesystem-heavy benchmark packages and shell-dependent toolrunner tests. Focused checks
passed under Git Bash with the existing Git utilities in PATH, `GOMAXPROCS=2` and an
accessible short temp root. The broker failures depend on the temp path; this observation
does not establish a precise socket-length threshold. A separate full invocation using
`C:\Windows\Temp` failed with access-denied errors and is retained as failed evidence.
The corrected full rerun used `TMP=TEMP=C:\Temp` and the CI command
`go test -p 1 -count=1 ./...` and passed with exit code 0. The raw Go log and the separate
terminal completion receipt preserve that result; the earlier failed run remains separate.
No source changes or skipped tests were used to accommodate these local environment failures.

The candidate was reconciled with main at `18186516`, including merged #1575.
That change affects Telegram response reading, decoding and delivery classification;
it does not change outbound formatting, captured facts or outbox semantics. The native
Telegram and Google Chat fixture journals predate that reconciliation. Their formatted
body and link evidence remains applicable; the current full-suite reruns separately
verify the updated sender. Capture-time runtime provenance is retained rather than
relabeled as a newer binary deployment.

## Local evidence artifacts

These summaries exclude credentials, receiver destinations, identifiers and message bodies.
They distinguish transactional source evidence from renderer/sender fixtures and native
client inspection. Each runtime receipt describes the candidate at its capture time; later
review fixes have separate regression evidence.

- [Current candidate build](assets/ui/notification-lifecycle/candidate-runtime-build.json):
  final API/worker binaries and reviewed web image installed in the three owned loopback
  containers. Earlier runtime receipts retain their original capture-time provenance.
- [Initial runtime evidence](assets/ui/notification-lifecycle/runtime-evidence.json):
  13 source instances across 12 event types, API/worker restart recovery and immutable
  captured facts; 288 deliveries, 244 delivered and 44 webhook HTTP429 dead letters.
- [Current approval roster evidence](assets/ui/notification-lifecycle/current-approval-runtime.json):
  four real approval sources and four private recipient rows; repeated helper leaves
  captured facts unchanged. Its point-in-time delivery states remain unchanged in this receipt.
- [Fresh receiver source evidence](assets/ui/notification-lifecycle/fresh-receiver-source-runtime.json):
  four fresh real approval sources plus two rescheduled window sources; all 144 deliveries
  delivered. The receiver verified HMAC for all 24 actual webhook requests. Original webhook
  channel destinations, secrets and metadata were restored after the test.
- [Webhook captured-fact transport evidence](assets/ui/notification-lifecycle/webhook-captured-fact-transport.json):
  all 44 shared-event locale/class cells correlated once by delivery ID and exact body digest.
  Every receiver HMAC verified. One known HTTP429 attempt was absent from both receivers;
  continuation sent only unacknowledged cells. Canonical structured webhook envelopes are
  locale-invariant. Version-fenced redrive refused old jobs with HTTP409; no jobs were retargeted.
- [Mattermost/Rocket.Chat transport evidence](assets/ui/notification-lifecycle/captured-fact-transport-fixture.json):
  88 labelled captured-fact posts, without domain/outbox writes. They supersede the earlier
  invalid generic fixture that omitted event `Data`.
- [JSM captured-fact transport evidence](assets/ui/notification-lifecycle/jsm-captured-fact-transport.json):
  44 accepted requests with confirmed native alias bindings, rendered by the current service
  and sender. [Native JSM matrix](assets/ui/notification-lifecycle/jsm-native-matrix.json)
  records all 88 event/locale/class/theme cells, with exact expected notes and current
  alert identity checked before and after capture. Every content, notes and Details
  image was individually reviewed. Loading frames were replaced before acceptance.
  All 56 Details supplements show the deployment-owned console link; original Light
  theme was restored. Six source-event groups were clicked in the native client and
  checked against their exact console routes. Agent and governed-response features
  remain disabled on that deployment; no execution is claimed.
  Lifecycle creates include the sanitized rendered summary as a bounded note, preserving
  follow-up facts under an existing alias. Persisted request references resume with GET only.
  A lost POST response before reference persistence may duplicate an occurrence or note;
  already accepted older requests cannot gain missing notes through status resumption.
- [Native Slack matrix](assets/ui/notification-lifecycle/slack-native-matrix.json):
  all 88 shared event/locale/class/theme cells matched their provider-acknowledged message
  identity and were individually inspected. Six source-event groups were clicked to the
  exact deployed console routes. The original Operating System color mode was restored.
- [Native Mattermost matrix](assets/ui/notification-lifecycle/mattermost-native-matrix.json):
  all 88 shared event/locale/class/theme cells bound to the 44 corrected fixture post IDs
  and individually inspected. Six source-event groups were clicked to exact deployed
  console routes; destination images were reviewed. Original Onyx theme was restored.
- [Native Rocket.Chat matrix](assets/ui/notification-lifecycle/rocket-chat-native-matrix.json):
  all 88 shared event/locale/class/theme cells were individually inspected and bound to
  the 44 corrected fixture receiver IDs. Six source-event groups were clicked to exact
  deployed routes; destination images were reviewed. Original Match system mode was restored.
- [Native Telegram matrix](assets/ui/notification-lifecycle/telegram-native-matrix.json):
  all 88 shared event/locale/class/theme cells passed final review and six source-event
  destination groups were checked from native messages. The cells use the current renderer
  and `Sender.Send` normal-HTTPS fixture journal, with full formatted text, body digest and
  exact public link matched in private receipts. Bot API acknowledgements and Web recipient
  identities are distinct private values. The responsive capture viewport was 835x552 CSS;
  its prior browser override was reset, the original System theme was restored, and the old
  responsive test tab was closed. `finding.mentioned` is personal-only. `response.finished`
  and `evidence.chain_broken` use bounded synthetic facts and do not claim a remote response
  execution or live custody mutation. The native sidebar and content below the captured
  viewport are outside this evidence.
- [Native Discord matrix](assets/ui/notification-lifecycle/discord-native-matrix.json):
  all 88 shared event/locale/class/theme cells passed final review and six source-event
  destination groups were checked from native messages. The matrix correlates original
  runtime delivery acknowledgements surfaced by Discord native search; it is not a fresh
  provider-fixture run. Original Dark theme was restored. `response.finished` and
  `evidence.chain_broken` use bounded synthetic facts and do not claim a remote response
  execution or live custody mutation. The approval destination establishes the selected
  Agent route only; it does not establish copy or controls outside the captured viewport.
- [Native Google Chat matrix](assets/ui/notification-lifecycle/google-chat-native-matrix.json):
  all 88 shared event/locale/class/theme cells were individually reviewed. Native message
  identity matches both acknowledgement components, and complete formatted text matches
  the 44 current-renderer fixture deliveries. Six native Open buttons were clicked to
  their exact deployed console routes; all destination images passed review. The original
  Light theme and expanded main menu were restored. Open controls are buttons, so exact
  URL claims rely on actual click destinations rather than an HTML href. Finding comments
  and Agent-disabled copy below the captured viewport are outside the visual claim.
- [Native console/client inventory](assets/ui/notification-lifecycle/console-evidence.json):
  screenshots, inspected views and scoped acceptance completion. Response/custody
  client fixtures do not prove a remote response execution or live custody failure.

`finding.mentioned` remains personal-only; shared fixture matrices exclude it. Mention
routing, permissions, rollback and captured recipient identities are verified by tests and
the native personal inbox. A real Slack contact was linked through a native challenge, then one canonical mention
produced one personal inbox recipient and one completed Slack job with zero shared
deliveries. The native DM link opened the correct finding. Its temporary preference was
restored; credentials and the used code are absent from the screenshots. See
[personal mention evidence](assets/ui/notification-lifecycle/personal-mention-runtime.json).
This uses the existing generic English personal notice; B06 still owns broader personal
locale and preference acceptance.

The eight-provider native locale/class/theme matrix and required clicked deployed links
have been inspected. Engineering readiness does not close the leaves automatically.
SMTP, Teams and PagerDuty are outside this batch's live evidence by the maintainer's #1576
deferral. No issue closure, commit, push, PR or merge is performed by this verification.

The [webhook native matrix](assets/ui/notification-lifecycle/webhook-native-matrix.json)
contains 88 individually reviewed receipt/envelope images and six clicked deployment
destinations. All 44 current-renderer requests reached a loopback-only receiver with
verified HMAC and raw-body digest. Webhook JSON remains locale-neutral; EN/VI cells
prove separate requests rather than translated JSON. This private test transport does
not change production HTTPS or egress policy.
