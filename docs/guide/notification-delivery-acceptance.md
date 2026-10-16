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
The initial local checks do not establish external delivery. The later live-provider
run below adds Slack, Telegram and Google Chat receipts only. This packet does not claim
a usable Teams bot identity or accepted Teams client evidence. Any outstanding leaf is referenced with
`Refs`, not closed by a code-only result.

PagerDuty live acceptance is deferred to [#1576](https://github.com/KKloudTarus/synapse-ce/issues/1576)
by the maintainer because no PagerDuty access is available. The remaining eligible
pager-class digest receipts, locale/theme rendering, deduplication and resolve evidence
stay unverified there. This deferral does not count as provider acceptance or close #1576.

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

## Gate repair verification on 2026-10-16

The two initial baseline failures below are repaired. The CLI pins Git's `a/` and `b/`
header prefixes, independently of mnemonic/custom/no-prefix presentation, and disables
external diff/text conversion. Correct-module coverage measures 100%; an unmatched module
still fails its coverage condition. Regression cases exercise each presentation setting
and both converter paths.

The systemd sandbox fallback now sets `MemorySwapMax=0` whenever it sets `MemoryMax`,
matching the direct cgroup policy. Before the fix, the local scope had
`memory.max=67108864` and `memory.swap.max=max`, allowing the memory bomb to finish its
1 GiB allocation loop through swap. Process limits remain unchanged. The test now requires
allocation-loop evidence and non-successful termination, rejects setup errors, and uses
strict bounds of at most 63 forks and less than 64 MiB of reported allocations.

| Current check | Observed result |
| --- | --- |
| Full Go suite, `GOMAXPROCS=2 go test -p 4 -json ./...` | Exit 0; 17,318 pass / 709 conditional skips / 0 fail, including subtests. |
| `go build ./...`, `go vet ./...`, `golangci-lint run ./...` | Pass; lint reports `0 issues.` |
| Race checks for gitdiff, sandbox and CLI | Pass, 1.320s / 2.292s / 1.525s respectively. |
| Real containment in ordinary local session | Pass: 61 child forks, 48 MiB reported allocation, termination exit -1. |
| Real containment in a `systemd-run --user --scope -p Delegate=yes` scope | Pass: 61 child forks, 48 MiB reported allocation, termination exit 137. |

Reported allocations are progress telemetry from the test workload, not a measured
resident-memory peak. Neither containment run skipped. The narrower Git/sandbox fixes do
not change notification persistence, rendering or frontend code; the PostgreSQL/browser/
frontend evidence below remains bound to the original notification implementation.
The full local Taurus gate passes; external-client acceptance remains incomplete as
listed below. After rebuilding and restarting the local API and worker, readiness passes
and both retained hourly/daily SMTP payloads still match current preview text and HTML.
The PR stays Draft, uses `Refs` and is not merged.

## Initial verification recorded on 2026-10-16

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

The initial full Go gate was **red** because both failures below also occurred at pristine
`b88812e15fce7c88604bc735872532fe5cae75f3`:

```text
TestRunGateStripsGoModulePathForNewCodeCoverage:
  coverage >= 50 (no data)
  new-code coverage floor must pass once the module path is stripped
TestCgroupContainsBombs:
  memory bomb NOT contained: reached 1024MB under a 64MB cap
```

These failures were fixed and rechecked without skipping or weakening them. No issue is
closed while its complete DoD or external-client evidence is outstanding.

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
the complete real-client preview/send pair matrix, mixed-event hourly/daily client
matrices and dark/mobile coverage, and the Teams link/contact/message/history/navigation
journey. The later live run below covers five finding.created events across en/vi and
signal/detail on three desktop clients. Keep
#1420 open. Use `Refs` for #1372, #1374, #1377, #1417, #1420, #1421 and #1422; retain
#1418/#1419 as already closed integrations. Ownership is unchanged.

## Live provider verification on 2026-10-16

The [live evidence record](assets/notification-live-delivery-evidence.json) records
24 actual queued digest deliveries: Slack in the maintainer-selected JJ workspace,
the existing Telegram test bot, and the existing Google Chat test space. Each provider
received hourly and daily digests for en/detail, en/signal, vi/detail and vi/signal.
Every job reached `delivered` with HTTP 200 and one attempt. Native message text contained
all five severity rows; detail contained finding titles and signal omitted them.
An actual worker restart preserved the same 24 event/delivery identities and one attempt
per job. This establishes that bounded restart case, not a concurrency or soak result.

Five findings were created through the API for each cell, with high/medium/low/info/high
severity. These remain five `finding.created` events, not five different event types.
Only these fixture rules' windows were moved into closed periods before the actual worker
published them. No elapsed hourly/daily soak is claimed. The en/detail run used the exact
Google Chat patch before its commit; the other three cells used binaries built from clean
`eb41dbf7e07c11d9610e8347e38718e2f9e2ae45`. Binary and patch hashes distinguish them.

Native correlation uses Google provider message references, unique engagement/finding
links plus cadence in Slack, and Telegram timestamps within two seconds of the matching
attempt plus cadence/content. Telegram web DOM IDs differ from Bot API message IDs;
the packet does not claim direct ID equality there. Eighteen stored-event preview bodies
matched native body lines. Six previews returned 404 because their events fell outside
the newest-twenty selection ordered by `occurred_at` and ID. Those six are explicitly
unverified for preview parity. Fixture send-tests also reached each provider in en/detail;
the complete console-preview/send pair matrix remains open.

### Google Chat standalone digest repair

The first two Google Chat digest jobs failed with HTTP 400 while a fixture send-test
succeeded. A real provider diagnostic reported: “The request does not specify which
message to reply to.” The driver had requested reply fallback without a subject thread.
It now adds that reply option only with a subject-derived thread key. Fresh hourly/daily
digests succeeded through the real worker. The original failed attempts remain in history;
two manual diagnostic posts are excluded from queued acceptance.

The new standalone regression failed with HTTP 400 before the repair and passed after it.
Focused sender/usecase/formatter checks and sender race tests pass. The full Go run now
records **17,319 pass / 709 conditional skips / 0 fail**, including subtests. Vet, lint
(`0 issues.`), static API/worker builds and docs checks pass. Independent QA and security
reviews pass for this adapter change. The earlier PostgreSQL and frontend results remain
bound to their unchanged surfaces; they were not rerun for this adapter-only repair.

### Representative native receipts

The frontend reviewer inspected all twelve images and found no credentials, private
sidebars or unrelated people. Two English Google screenshots crop the start of the space
header; the complete representative cards remain readable and the daily app sender is
visible. These images show desktop light-mode receipts. Initial en/detail Telegram and fixture
images retain their pre-fix source label in the JSON; they are not evidence of the Google
Chat repair. Screenshots do not establish authenticated console navigation.

| Native client | Captures |
| --- | --- |
| Slack, JJ test channel | [en/detail](assets/ui/notification-delivery/live/slack-digests-en-detail-light.jpg), [vi/signal](assets/ui/notification-delivery/live/slack-digests-vi-signal-light.jpg) |
| Google Chat test space | [en/detail hourly](assets/ui/notification-delivery/live/google-chat-hourly-en-detail-light.jpg), [en/detail daily](assets/ui/notification-delivery/live/google-chat-daily-en-detail-light.jpg), [vi/detail daily](assets/ui/notification-delivery/live/google-chat-daily-vi-detail-light.jpg), [vi/detail hourly](assets/ui/notification-delivery/live/google-chat-hourly-vi-detail-light.jpg), [vi/signal hourly](assets/ui/notification-delivery/live/google-chat-hourly-vi-signal-light.jpg) |
| Telegram test bot | [initial en/detail hourly](assets/ui/notification-delivery/live/telegram-hourly-en-detail-light.jpg), [initial en/detail daily](assets/ui/notification-delivery/live/telegram-daily-en-detail-light.jpg), [vi/detail hourly](assets/ui/notification-delivery/live/telegram-hourly-vi-detail-light.jpg), [vi/signal hourly](assets/ui/notification-delivery/live/telegram-hourly-vi-signal-light.jpg) |
| Google Chat fixture test | [en/detail receipt](assets/ui/notification-delivery/live/google-chat-preview-test-en-detail-light.jpg) |

### Remaining client boundaries

The complete theme/device matrix, mixed-event digests, authenticated deep-link clicks and
all locale/class console-preview/send pairs remain incomplete. Telegram web displayed the
localhost finding labels without anchor elements; its navigation acceptance remains
unverified. No public console route was substituted. Slack and Google Chat native links
were observed, but destination navigation was not accepted while the local console was
logged out.

The existing Discord test server/webhook was found, but its credential could not be handed
off through the browser clipboard; no Discord receipt is claimed. The logged-in Teams
account is personal and does not establish the dedicated Microsoft 365 bot, verified link,
contact/history and navigation required by #1420. Keep that issue open.

Gmail/Outlook login alone does not establish SMTP credentials or transport acceptance.
School-account GCP inspection stopped at reauthentication; the maintainer then prohibited
billing or organization-impacting setup there and allowed a personal-account fallback.
The personal account's project search returned no resource named Synapse; the displayed
project had no OAuth client. No new project, API enablement, billing, credential or mail
grant was created. No Gmail/Outlook SMTP receipt is claimed. PagerDuty remains deferred
to #1576. The PR stays Draft with `Refs`; ownership and issue closure policy are unchanged.
