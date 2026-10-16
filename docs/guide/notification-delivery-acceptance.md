# Notification delivery acceptance

This packet tracks the remaining B06 work from the external integrations plan against
baseline `b88812e15fce7c88604bc735872532fe5cae75f3`. Issue ownership is unchanged:
`pho-veteran` retains the preview/digest assignments and progress; the existing
`XUanhoa04` claims and merged personal-delivery/inbox implementation are retained.

## Acceptance ledger

| Issue | Merged baseline and remaining implementation | Closure condition |
| --- | --- | --- |
| #1372 | Reuse #1545 and #1566; call the shared renderer, apply destination/engagement policy, show suppression, safe fallback and latest fixtures. Stored samples are limited to the newest twenty readable events. | Integrated route, permission, tenant, class/suppression and rendering tests. No external-client screenshot is required by this issue. |
| #1374 | Add the template-editor preview, sandboxed email HTML and fixture-only queued test using an immutable template snapshot and the shared test quota. | Real-client preview/test pairs remain distinct from local transport and browser evidence. |
| #1377 | Add immediate/hourly/daily rules, transactional membership, tenant-keyed closed windows, per-item filtering, mandatory/critical bypass, safe counts, retries and admission-policy witnesses. | Hourly five-item and daily live-client evidence, plus idempotency/concurrency and PostgreSQL checks. |
| #1418 / #1419 | Already closed through merged #1571. Keep preferences, mandatory floors, explicit verified linking, contact versions and personal delivery. | Run integration regressions; do not reopen or reimplement accepted work. Historical Slack evidence keeps its tested commit. |
| #1420 | Retain the merged Teams bot/link-code/contact/personal-delivery code. | **Open** until real Teams linking, verified contact, message/history correlation, correct console navigation and reviewer-inspected screenshots exist. Fake-service tests do not satisfy this. |
| #1417 | Retain the existing bell/inbox, filters, read operations and user-scoped API. | Actual console journey and relevant loading/empty/error/permission states, with per-user isolation tests. |
| #1421 | Reuse engagement/team pickers and missing-ID retention; add explicit personal-recipient IDs, minimal managed user search and round-trip persistence. | Picker behavior/permission/tenant tests and console evidence. Missing IDs stay saved; disabled/foreign users receive nothing. |
| #1422 | Extend the existing mandatory admin notice to email create/domain-set changes. Keep HTTP v1 schemas; publish email-capable v2. | Atomic/revision-deduped domain-only notices and mandatory inbox/isolation tests; same-domain edits, metadata and credential rotation emit no notice. |

## Design and invariants

Digest membership is captured when an existing rule matches an original event, within the
same tenant transaction. This avoids replaying historical events through today's rules.
UTC publication-time windows prevent late source timestamps from reopening a sent window.
The window identity contains tenant, rule, channel, cadence and a continuation chunk.
Each chunk holds at most 200 members. Closing it and publishing its aggregate through `PublishToChannel` commit together. Disabled and empty outcomes are
also durable; re-enabling a rule cannot release an earlier suppressed chunk. Channel
disable, pause and destination/secret replacement cancel pending chunks atomically; later
valid events start a new chunk. Published authority survives rule deletion.

The original snapshots remain authoritative. Every load filters each member under its
current engagement override and the current destination ceiling, drops `none`, caps the
rendered list at fifty and preserves the allowed total/omitted count. Sorted engagement
locks and an admission witness reject a policy change between load and attempt. Critical
and mandatory events bypass batching. Original source relevance guards run again before
count, severity, rows, links and raw descriptors are derived; failed reads retry and expired
alerts contribute nothing. Personal routing remains immediate. Template tests
never fan out to real personal recipients.

Preview and queued template tests share `RenderMessage`, safe fallback and the channel
formatters. A test snapshots its selected template, so later edits cannot alter a retry.
Raw-event webhooks bypass templates and are refused by the template-preview/test API.
Fixture links open notification settings rather than a nonexistent fixture finding.

Email notice summaries contain sorted recipient domains only. A full recipient address
must not appear in the destination notice summary or context.
Secret values, credential-bearing URLs and unfiltered source contexts must not appear in
preview metadata, attempt history or this packet. Browser evidence uses only reserved
synthetic addresses and locally generated identities. Inbox rows remain self-scoped and
mandatory floors retain precedence over preferences.

## Local stack and evidence limits

The local acceptance environment uses the repository's full Compose stack with a separate
notification worker, PostgreSQL 17 under a non-superuser runtime role, MinIO and a local
HTTPS console. MinIO's removed public images required a local source build from the
upstream release tags; this is a real object store, not a mocked dependency. Private
credentials and local overrides stay outside the repository.

Local browser, database and transport checks establish only their measured boundaries.
They do not establish delivery in Slack, Teams, Telegram, Discord, Google Chat, Gmail,
Outlook or PagerDuty. In particular, this packet does not claim a usable Teams bot
identity or accepted real-client evidence. Any outstanding leaf is referenced with
`Refs`, not closed by a code-only result.

## Work bounds and recovery

The runtime exercise contains five manually authored findings; production source rates and
retained-window counts are unknown. Membership admission batches rule/channel targets into
one SQL write after the tenant scheduler and ordered channel locks. Pending windows use a
partial due index; aggregate lookup uses the tenant/event index. A chunk hydrates at most
200 source snapshots. Filtering and deterministic sorting take O(n log n) time and O(n)
space for n <= 200. At most fifty rows survive the sixteen-KiB context cap. Only event types
with an existing relevance callback require source reads, with at most 200 callbacks per
aggregate; no production latency or throughput claim is made.

Notification history and test snapshots remain immutable. The supported application
rollback keeps migration `0239` applied and stops producers/workers that could hand these
jobs to an older binary. Draining jobs cannot make Down possible after a retained pinned
test snapshot; use a forward fix rather than deleting history.

## Verification recorded on 2026-10-16

The [sanitized evidence record](assets/notification-delivery-evidence.json) contains the
captured payload hashes, binary hashes, screenshot hashes and PostgreSQL shard results.
Private credentials, contact challenges, database URLs and local Compose overrides are
excluded. The runtime database was freshly migrated through `0239`; both runtime roles
have `rolsuper=false` and `rolbypassrls=false`.

| Check | Observed result |
| --- | --- |
| `go build ./...`, `go vet ./...`, `golangci-lint run ./...` with Go 1.27.0 / golangci-lint 2.13.2 | Pass; lint reports `0 issues.` |
| `GOMAXPROCS=2 go test -p 4 -json ./...` with Helm 3.19.0 available | 17,307 pass, 709 skip, 2 fail; includes subtests. The two failures reproduce on the pristine baseline below. |
| All PostgreSQL tests, `-count=1`, partitioned by exact top-level name across four separate test databases | All 660 selected; every shard exit 0. 1,014 pass and 4 skip including subtests; 758.1 seconds wall time. |
| Focused digest/migration PostgreSQL regressions | Pass, 32.185s; channel transitions, same-window fresh chunks, rule history, contention, RLS and index plans. |
| Independent QA PostgreSQL transition/history/contention regressions | Pass, 16.678s. |
| Independent QA focused race checks | Pass, usecase 2.057s / memory 1.067s. |
| Full frontend suite under Node 22 / pnpm 9 | 199 files / 1,330 tests pass. After the final iframe color fix, all 11 preview tests, typecheck, lint and production build pass again. |
| Hostile HTTP tenant harness | Pass, `TestHostileHarness`, 0.021s. |
| Final email formatter checks | Pass; existing goldens, injection/link tests and all five typed severity levels. Unknown values receive no marker. |

The four PostgreSQL skips are the opt-in 100k assessment scale fixture, opt-in 10k ownership
scale fixture, explicit assessment browser helper, and response halt test requiring three
separate test-role DSNs. The notification tenant/RLS tests did execute. None of these
skips is a production capacity or recovery claim. Frontend lint retains eleven existing
warnings; the build retains its existing large-chunk warning.

The full Go gate remains **red** because both failures below also occur at pristine
`b88812e15fce7c88604bc735872532fe5cae75f3`:

```text
TestRunGateStripsGoModulePathForNewCodeCoverage:
  coverage >= 50 (no data)
  new-code coverage floor must pass once the module path is stripped
TestCgroupContainsBombs:
  memory bomb NOT contained: reached 1024MB under a 64MB cap
```

These failures were not skipped or weakened. The Draft must not be marked ready based on
this packet. No issue is closed while its complete DoD or evidence is outstanding.

The Taurus tier-0 QA, security and performance panel passed the reviewed implementation;
reliability and frontend specialists also passed. Confirmed cancellation, history,
relevance, lookup-index, recent-list hydration, snapshot-race and presentation findings
were fixed and rechecked. One low performance finding is deferred: equal-end pending
windows require sorting because the due index order differs from the queue order. Align
that ordering before making a queue-drain capacity claim; current local evidence does
not establish production capacity.

## Actual local journeys

The final full-stack run used the API, notification worker, PostgreSQL, real MinIO,
Mailpit with verified SMTP STARTTLS, nginx and the HTTPS console. The MinIO source tags
were `RELEASE.2025-09-07T16-13-09Z` and mc `RELEASE.2025-08-13T08-35-41Z`.
No external scan or customer destination was used.

- A fixture test queued from the editor reached the SMTP receiver. Subject, normalized
  text and normalized HTML matched the preview exactly; the record contains the HTML
  SHA-256. Pinned-template immutability and activation races are additionally covered by regression tests.
- Hourly and daily built-in email digests each contained five API-created findings with
  mixed severity, delivered once with one attempt, and matched their stored-event
  preview in both MIME parts. The window fixture explicitly moved publication windows
  to closed periods and restarted the actual worker to poll; this is not an elapsed
  hourly/daily soak, and the five findings are not five different event types.
- The browser opened the administrator notice's settings link and the reader's engagement
  link, retained the saved missing recipient ID in the searchable rule form, and exercised
  mark-all-read, unread empty, controlled request delay, actual transport abort, permission
  denial and a 390-pixel viewport. The loading/error captures do not use fake API payloads.
- Email destination edits produced deltas `same domain=0`, `metadata=0`, `domain set=1`;
  the actual mandatory notice summary contained domains only. PostgreSQL regressions also
  cover transaction rollback, stale revision, mandatory floors and foreign/disabled users.

| Captured surface | Evidence |
| --- | --- |
| Administrator notice and bell | [Inbox](assets/ui/notification-delivery/inbox-admin-domain-notice.png) |
| Selected people and missing saved ID | [Rule search](assets/ui/notification-delivery/rule-search-missing-recipient.png) |
| Queued fixture test | [Template editor](assets/ui/notification-delivery/template-email-preview-test.png) |
| Readable email preview | [Light](assets/ui/notification-delivery/template-email-preview.png), [dark](assets/ui/notification-delivery/template-email-preview-dark.png) |
| Reader inbox and unread bell | [Reader](assets/ui/notification-delivery/inbox-reader-bell.png) |
| Mark all read and unread empty | [Empty](assets/ui/notification-delivery/inbox-unread-empty.png) |
| Loading, transport error and permission denial | [Loading](assets/ui/notification-delivery/inbox-loading.png), [error](assets/ui/notification-delivery/inbox-network-error.png), [permission](assets/ui/notification-delivery/templates-permission-denied.png) |
| Mobile inbox | [390 px](assets/ui/notification-delivery/inbox-mobile.png) |
| Actual local SMTP digests | [Hourly](assets/ui/notification-delivery/smtp-digest-hourly-en-light.png), [daily](assets/ui/notification-delivery/smtp-digest-daily-en-light.png) |

The frontend reviewer inspected all thirteen images. Missing evidence includes the complete
light/dark/state matrix for every changed screen, cross-engine/screen-reader verification,
real-client preview/send pairs, mixed-event hourly/daily client matrices across en/vi and
signal/detail, and the Teams link/contact/message/history/navigation journey. Keep
#1420 open. Use `Refs` for #1372, #1374, #1377, #1417, #1420, #1421 and #1422; retain
#1418/#1419 as already closed integrations. Ownership is unchanged.
