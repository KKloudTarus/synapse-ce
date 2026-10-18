# Notification delivery acceptance

This packet tracks the remaining B06 work from the external integrations plan against
baseline `b88812e15fce7c88604bc735872532fe5cae75f3`. Issue ownership is unchanged:
`pho-veteran` retains the preview/digest assignments and progress; the existing
`XUanhoa04` claims and merged personal-delivery/inbox implementation are retained.

## Current acceptance scope

The maintainer accepts **one theme per client** for this PR. Additional theme/device
permutations are not merge requirements. Earlier reviewed captures remain as evidence;
they do not require another replay. Teams and PagerDuty are the only provider deferrals,
tracked in #1576 with Teams personal delivery retained in open #1420.

The final packet adds actual Outlook and Discord native receipts, six paired VI/signal
console previews, and representative mixed Slack/Telegram receipts from the existing
cohort. The chronological sections below retain the limits that applied at each earlier
checkpoint; the final reconciliation section supersedes their outstanding capture lists.

## Acceptance ledger

| Issue | Merged baseline and remaining implementation | Closure condition |
| --- | --- | --- |
| #1372 | Reuse #1545 and #1566; call the shared renderer, apply destination/engagement policy, show suppression, safe fallback and latest fixtures. Stored samples are limited to the newest twenty readable events. | Integrated route, permission, tenant, class/suppression and rendering tests. No external-client screenshot is required by this issue. |
| #1374 | Add the template-editor preview, sandboxed email HTML and fixture-only queued test using an immutable template snapshot and the shared test quota. | Real-client preview/test pairs remain distinct from local transport and browser evidence. |
| #1377 | Add immediate/hourly/daily rules, transactional membership, tenant-keyed closed windows, per-item filtering, mandatory/critical bypass, safe counts, retries and admission-policy witnesses. | Hourly five-item and daily live-client evidence, plus idempotency/concurrency and PostgreSQL checks. |
| #1418 / #1419 | Already closed through merged #1571. Keep preferences, mandatory floors, explicit verified linking, contact versions and personal delivery. | Run integration regressions; do not reopen or reimplement accepted work. Historical Slack evidence keeps its tested commit. |
| #1420 | Retain the merged Teams bot/link-code/contact/personal-delivery code. | **Deferred from this PR by the maintainer**, tracked in open #1420. Real Teams linking, verified contact, message/history correlation, console navigation and reviewed screenshots remain required there; fake-service tests do not satisfy them. |
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
preview metadata, attempt history or this packet. Published browser evidence excludes
private account headers and recipient addresses. Inbox rows remain self-scoped and
mandatory floors retain precedence over preferences.

## Local stack and evidence limits

The local acceptance environment uses the repository's full Compose stack with a separate
notification worker, PostgreSQL 17 under a non-superuser runtime role, MinIO and a local
HTTPS console. MinIO's removed public images required a local source build from the
upstream release tags; this is a real object store, not a mocked dependency. Private
credentials and local overrides stay outside the repository.

Local browser, database and transport checks establish only their measured boundaries.
The initial local checks do not establish external delivery. The later live-provider
runs below add Slack, Telegram, Google Chat and a public HTTPS receiver. This packet does not claim
a usable Teams bot identity or accepted Teams client evidence. Any outstanding leaf is referenced with
`Refs`, not closed by a code-only result.

Teams and PagerDuty live acceptance are deferred together to
[#1576](https://github.com/KKloudTarus/synapse-ce/issues/1576). Teams personal-delivery
acceptance also remains tracked in open
[#1420](https://github.com/KKloudTarus/synapse-ce/issues/1420), with ownership unchanged.
The Teams bot/link-code/contact implementation remains in this PR, but real Microsoft 365
linking, contact, message/history and navigation evidence is not accepted or claimed.

PagerDuty live acceptance is deferred to [#1576](https://github.com/KKloudTarus/synapse-ce/issues/1576)
by the maintainer because no PagerDuty access is available. The remaining eligible
pager-class digest receipts, locale/theme rendering, deduplication and resolve evidence
stay unverified there. This deferral does not count as provider acceptance or close #1576.

## Work bounds and recovery

The initial runtime exercise contains five manually authored findings. The later mixed run
uses five distinct API-produced types per cell; production rates and retained-window counts
remain unknown. Membership admission batches rule/channel targets into
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
At this verification stage the PR stayed Draft, used `Refs` and was not merged.

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

The subsequent run adds mixed-event digests and Google Chat light/dark captures. The full
provider/device and console-preview/send matrices remain incomplete. Telegram localhost
labels lack anchors; navigation remains unverified. One Google Chat fixture button opened
the correct notification settings route. Normal API-key sign-in retained that route and
the delivered attempt was inspected. This establishes that bounded authenticated journey;
it does not establish every source link or automatic session sharing between tabs.

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
to #1576. This live-verification stage retained Draft with `Refs`; ownership and issue
closure policy were unchanged.


## Mixed-event implementation and live verification on 2026-10-16

The [mixed-event evidence record](assets/notification-mixed-delivery-evidence.json) keeps
this cohort separate from the older finding-only receipts. A rule explicitly selects at
most eight types while retaining its legacy primary selector. Shared filters, recipients,
team scope, lead times and bindings validate every type. Omitting the selection cannot
silently narrow an existing explicit selection. The searchable additional-event picker
retains saved missing IDs and blocks incompatible selections. Chat preview shows the title
before the body and a typed severity badge. Digest items without severity omit brackets.

Migration `0240` preserves legacy rules. A transaction capability marker makes an older
publisher fail closed for matching enabled multi-type rules. The fence cannot detect an
old scheduler that never emits a secondary event: upgrade every API, source scheduler and
worker before enabling these rules. Scheduled lead queries now match secondary types.
Stop producers and the materializer before disabling rules to preserve pending work;
running the materializer while a rule is disabled permanently suppresses its pending window.
The notification runbook documents rollout and rollback.

### Actual heterogeneous receipts

Four cells cover en/vi and detail/signal. Each creates an engagement, changes its status,
creates a finding, changes its status and comments through the real API. The five stored
types are `engagement.created`, `engagement.status_changed`, `finding.created`,
`finding.status_changed` and `finding.commented`. Two rules select all five and send
hourly/daily windows through the real worker to Slack JJ, Telegram, Google Chat and a
public HTTPS receiver.

All **32 digest jobs** delivered HTTP 200 once, with five members. An actual worker restart
and forty-second observation preserved every event/delivery identity, remote reference and
single-attempt count. Fixture windows were explicitly closed; no elapsed hourly/daily soak
is claimed. Cell provenance includes the base commit, tracked patch, untracked source and
actual binary hashes rather than claiming a clean committed build.

All 24 chat receipts were found in native clients. Google matches exact provider message
IDs; Slack matches unique engagement links and cadence; Telegram matches native server
timestamps within the actual request interval with one-second rounding, plus cadence and
content. Telegram DOM IDs differ from Bot API IDs. Each digest contains all five types
once. Detail includes the synthetic finding title; signal omits it. Ten stored chat
previews match native body lines. Fourteen previews returned 404 outside newest-twenty
sample selection and remain unverified for parity.

The public receiver captured eight webhook requests. Every versioned envelope parsed with
five typed items and verified HMAC. Four available previews match received bytes; four
remain outside sample selection. Receiver URL tokens, signatures, IPs and credentials are
excluded. An earlier private-address receiver attempt was correctly blocked by SSRF and
is excluded from these successful receipts. Sender protections remain enabled.

Twelve fixture tests across three chat providers and four locale/class cells delivered
HTTP 200 once. All four Google fixture cards match provider reference, preview title and
body lines in the native thread. One editor-initiated test has the authenticated settings
and attempt-history journey above. The complete console-preview/send/navigation matrix
remains unverified.

### Reviewed captures

All sixteen Google digest images and both console previews were individually reviewed;
hashes match. Every digest card shows title, cadence, five typed rows and five buttons.
Medium severity is textual where present, with a yellow marker. Vietnamese framing and
diacritics remain intact; enum strings and source labels remain English. No credential or
private sidebar appears. Pixels establish rendering; separate records establish correlation.

| Surface | Light | Dark |
| --- | --- | --- |
| Google en/detail hourly | [Light](assets/ui/notification-delivery/mixed/google-chat-mixed-hourly-en-detail-light.jpg) | [Dark](assets/ui/notification-delivery/mixed/google-chat-mixed-hourly-en-detail-dark.jpg) |
| Google en/signal daily | [Light](assets/ui/notification-delivery/mixed/google-chat-mixed-daily-en-signal-light.jpg) | [Dark](assets/ui/notification-delivery/mixed/google-chat-mixed-daily-en-signal-dark.jpg) |
| Google vi/detail daily | [Light](assets/ui/notification-delivery/mixed/google-chat-mixed-daily-vi-detail-light.jpg) | [Dark](assets/ui/notification-delivery/mixed/google-chat-mixed-daily-vi-detail-dark.jpg) |
| Google vi/signal hourly | [Light](assets/ui/notification-delivery/mixed/google-chat-mixed-hourly-vi-signal-light.jpg) | [Dark](assets/ui/notification-delivery/mixed/google-chat-mixed-hourly-vi-signal-dark.jpg) |
| Console preview | [en/signal](assets/ui/notification-delivery/mixed/console-preview-en-signal-light.jpg) | [en/detail](assets/ui/notification-delivery/mixed/console-preview-en-detail-dark.jpg) |

The JSON contains all eighteen hashes and remaining captures. Slack dark mode, Telegram
navigation, the full provider/device matrix and every changed screen's full state/theme
matrix remain incomplete. Teams, Discord, Gmail/Outlook SMTP and PagerDuty retain the
boundaries above. No mock supplies external acceptance.

### Current engineering gate

| Check | Actual result |
| --- | --- |
| Full Go 1.27.0 suite with Helm 3.19.0, `GOMAXPROCS=2 go test -p 2 -json ./...` | Exit 0; 17,341 pass / 713 conditional skips / 0 fail, including subtests. |
| Go build, vet and golangci-lint 2.13.2 | Pass; zero lint issues. |
| Domain/usecase/memory notification race checks | Pass. |
| Full frontend, Node 22 / pnpm 9, two workers | 200 files / 1,342 tests pass; typecheck, lint and build pass. Eleven existing lint warnings. |
| Full PostgreSQL selection, four databases | 662 top-level tests; 1,022 pass / 4 skip / 1 setup failure, including subtests. |
| Final serial PostgreSQL notification/migration and failed-case rerun | 155 pass / 0 fail, including final secondary-event source regressions. |
| Actual full stack | PostgreSQL 17, MinIO, Mailpit STARTTLS, API, worker, web and HTTPS; ready with schema 0240. |

The PostgreSQL shard failure was a cluster-global test-role password collision in
`TestBitbucketWebhookConcurrentPayloadReplaysEnqueueOnce`. Separate database shards altered
the same role. The serial rerun passed. These are separate runs, not one clean full
invocation. Four opt-in skips remain as listed above; notification/RLS tests executed.

Tier-0 QA, security, performance, architecture, reliability and frontend reviews pass.
A low recovery-documentation finding was fixed by documenting the materializer stop before
rule disable. A restricted-role warm query over 24 rules and 76 joined rows used indexed
tenant/team lookups, zero disk reads and 0.599 ms execution. This small observation does
not establish production capacity. Hot-tenant contention, sustained drain and production
latency remain unmeasured; the earlier due-window ordering follow-up is retained.

The maintainer authorized Ready for review after deferring Teams and PagerDuty together.
Both deferrals are tracked in open #1576, with Teams personal delivery also retained in
open #1420; neither issue is closed or
counted as accepted. The implementation gate passes, and the remaining client-evidence
limits above stay explicit with `Refs`. #1418/#1419 remain closed integrations and ownership
is unchanged. At that checkpoint, Ready for review did not authorize merge or auto-merge.

## Evidence reconciliation and compatibility on 2026-10-17

The maintainer subsequently authorized a fix/review loop and merge only after approval.
Teams and PagerDuty remain deferred to #1576, and #1420 remains open. Other missing
client evidence is not converted into an accepted result by that instruction.

The previous PRs were checked against their complete bodies and review comments:

| Merged PR | Evidence retained with its original boundary |
| --- | --- |
| #1571 | Fourteen reviewed captures cover Slack contact linking, challenge, verified contact, DM, personal defaults, inbox and destination navigation. Teams was unavailable. |
| #1572 | Commit `a8e2d1b9` sent ten actual Gmail SMTP/XOAUTH2 self-mails. Its grants were revoked. The later `993fc712` URL-defanging check used Gmail UI self-send, rather than another SMTP run. Outlook had no accepted live transport result. |
| #1574 | Real queued source/outbox/worker receipts and trusted HTTPS destination journeys were recorded for the providers named in that packet. Earlier Gmail receipts were retained as history, rather than a fresh event matrix. |
| #1583 | Eight provider manifests contain 88 reviewed cells each, 704 total, and six clicked source/destination groups per provider. Some rows use renderer/sender fixtures; these do not prove a fresh source or live host/custody failure. Slack personal delivery and an actual finding journey were exercised. Telegram anchors worked with the trusted deployed HTTPS base. |

These are accepted historical boundaries, not new preview/send-test or mixed-digest
receipts. The localhost Telegram limitation above does not establish that Telegram
cannot navigate a trusted HTTPS console. The current source retains those merged paths.

The first independent full-candidate review found that an older client omitting
`cadence` or `recipient_user_ids` could silently reset a digest rule or its selected
people. Updates now reject omitted cadence on a saved digest and omitted/null recipients
on a rule with explicit people. Deliberate `immediate` and `[]` still clear them;
legacy immediate rules without explicit people remain compatible. The saved rule stays
unchanged on rejection, and its pending digest still produces a delivery containing its
source event. The API contract and notification guide describe the update requirements
and the existing cadence/channel edit lifecycle.

| Current compatibility check | Actual result |
| --- | --- |
| Usecase regression against the previous service through a Go overlay | All eight omission cases fail as expected before the fix. |
| Real PostgreSQL regression against the previous service | Both hourly and daily cases reproduce the silent update. |
| Full affected notification/domain/sender/memory/HTTP/API/docs selection | 2,302 pass, one skip, zero fail. |
| Targeted race, full Go build, affected vet and lint | Exit 0. |
| Final real PostgreSQL regression, including retained digest event/delivery assertions | Pass, 1.513 seconds. |
| Independent compatibility QA | Pass; its low missing delivery assertion was fixed and rerun. |

The earlier broad PostgreSQL follow-up had three failing test records caused by comparing
UTC and scanned local-time representations. Re-reading the persisted baseline fixed the
comparison; the final focused run above is separate from that earlier invocation.
Previous full-suite, frontend, containment and RLS evidence remains bound to unchanged
surfaces; it is not represented as a new full-suite execution.

### Personal Gmail SMTP and native receipt evidence

The restored full Docker stack uses PostgreSQL 17, the restricted runtime role, MinIO,
Mailpit STARTTLS, separate API/worker services and the trusted local HTTPS console.
Schema `0240` and readiness were checked. The API and worker include the compatibility
guard above; the evidence record identifies their actual binary hashes and dirty-source
provenance rather than describing them as a clean release build.

With the maintainer's explicit consent, an existing personal Google project supplied a
Testing desktop OAuth client, one self-test user and the SMTP mail scope. No project,
billing change, compute resource or school-organization API enablement was created for
this run. An accidentally exposed, ungranted client was deleted before the replacement
client was authorized. Client secrets, tokens, consent details and recipient addresses
remain private. The temporary test grant must be revoked after this PR.

The [mail and Discord evidence record](assets/notification-mail-delivery-evidence.json)
separates these new observations from the historical PR evidence above:

| Surface | Actual observation |
| --- | --- |
| Gmail transport and mailbox | Four fixture tests, eight mixed digests and one actual editor send: 13 deliveries, one SMTP `250` attempt each, with exactly one matching Message-ID in the recipient Inbox. |
| Gmail parity | Received MIME subject, plain text and HTML match the captured previews for all 13 messages. Only transport line endings and terminal newlines are normalized. |
| Gmail mixed digests | All eight en/vi × signal/detail × hourly/daily combinations contain the five normal API-produced types listed above. Each cohort has eight windows and forty members. Windows were explicitly closed early; no elapsed-hour/day soak is claimed. |
| Gmail native rendering | Sixteen reviewed digest body crops and eight fixture body crops cover the desktop client's light/dark observations. Detail includes the synthetic finding title; signal omits it. Vietnamese framing is intact; source labels and enum values retain English text. |
| Gmail destination navigation | A digest finding link and the editor fixture's notification-settings link reached the correct local console route after normal API-key login. Exact destinations and the selected delivery are retained separately from pixels. |
| Discord transport and native DOM | Four fixture tests and eight mixed digests delivered once with HTTP `200`. Exact stored provider message IDs correlate all twelve native messages. Incorrect viewport captures are withheld; they do not supply visual acceptance. |
| Outlook receiver | A probe sent through Gmail OAuth SMTP was actually visible in the self-owned Outlook web mailbox. A further four fixtures and eight mixed digests have one SMTP `250` attempt each; their twelve native receipts, headers and rendering remain to be verified. This does not exercise Microsoft SMTP. |

The Gmail crops omit mailbox headers, addresses and private sidebars. Dark client mode
retains the template's white HTML body. Fixture detail/signal images share hashes when
the fixture contains only signal-level facts; the record discloses these duplicates
rather than counting distinct visual observations. No mobile or complete client-chrome
coverage is claimed.

The image review found private recipient addresses in an attempted history capture,
missing preview bodies in two console crops and incorrectly labeled console themes.
Those images are withheld. Later console and Discord captures also showed viewport
mismatches despite correct DOM state. They cannot establish preview/send visual pairs.
The browser connection then became unavailable before Outlook correlation and replacement
captures could finish. These are outstanding acceptance work, not additional provider
deferrals. Teams and PagerDuty remain the only maintainer-approved deferrals.


## Final native-client reconciliation on 2026-10-17

The machine restart preserved the private receipts, original native frames, logs and
runtime configuration in a repository-local private checkpoint. The same Docker volumes
and binaries were restored. API, worker, PostgreSQL, MinIO, Mailpit, web and HTTPS resumed;
readiness passed. All 69 recorded deliveries retained exactly one successful attempt;
nonempty expected provider references were unchanged. No new delivery cohort was needed for the remaining Slack/Telegram
captures, and no mock stands in for a client receipt.

| Client | Accepted current evidence |
| --- | --- |
| Gmail | Thirteen exact Message-ID Inbox receipts with subject/plain/HTML parity; reviewed fixture and mixed digest body crops; actual editor send and settings/finding destination journeys. |
| Outlook web | Twelve exact native Message-ID/decoded-subject bindings: five Inbox and seven Junk. Visible body/link parity and 24 reviewed native crops; actual settings and finding navigation. Transport is Google OAuth SMTP to Outlook, not Microsoft SMTP. |
| Discord | Twelve provider-ID-bound receipts and twelve reviewed dark native crops. Visible title/text/link groups match all twelve previews after native Markdown normalization. Actual fixture settings and digest finding links reached the authenticated console. This is semantic rendered parity, not original HTTP payload-byte equality. |
| Slack | Existing HTTP-200 queued cohort and native timestamp/source/cadence correlations; new light hourly EN/detail, daily VI/signal and VI fixture crops. Prior accepted personal-link/DM and trusted HTTPS destination evidence is retained with its original provenance. |
| Telegram | Existing HTTP-200 cohort and native timestamp/cadence/content correlations; new dark hourly EN/detail, daily VI/signal and VI fixture crops. DOM IDs differ from Bot API IDs. The fixture's English reply quote is native client context; the current VI message is complete. |
| Google Chat | Existing exact provider-reference mixed cohort and reviewed captures; one new exact-reference VI fixture crop paired with its console preview. Clicking that fixture's Open notifications button reached Channels at the correct settings route with the existing authenticated session. |
| Signed webhook | Existing eight parsed real HTTPS requests contain five typed members and verify HMAC; receipt and available preview-byte comparisons remain in the mixed packet. |

The [mail/Discord manifest](assets/notification-mail-delivery-evidence.json) and
[paired console/client manifest](assets/notification-preview-client-evidence.json)
retain exact delivery identities, hashes and normalization boundaries. Six console
previews use an unsaved clone of the same built-in finding fixture fields; no template
was activated. Native fixture receipts are paired by provider and locale, rather than
claiming that a screenshot itself proves transport. The earlier editor-initiated Gmail
send and Google Chat test journey establish the actual queued UI action separately.

The new console images show light visible panels. Telegram and Discord native images
show their existing dark appearance; each satisfies the one-theme scope. Every new crop
was individually inspected and its hash checked. Crops are literal rectangles of native
screenshots, with original/crop hashes and coordinates retained. Full frames, mailbox
headers, addresses, credentials and unrelated sidebars are withheld. Truncated provider
selector labels are normal UI truncation; the rendered message is complete.

The [preview state manifest](assets/notification-preview-state-evidence.json) links the
reviewed [loading](assets/ui/notification-delivery/states/preview-loading-light.png),
[error](assets/ui/notification-delivery/states/preview-error-light.png) and
[empty](assets/ui/notification-delivery/states/preview-empty-light.png) panels.
Preview loading was captured while the actual API container was paused with a request
outstanding. Killing that local container produced nginx HTTP 502 and the displayed
preview error; restarting it restored healthy readiness. The empty state uses an unsaved
Pager draft with no compatible enabled channel. No intercepted or fabricated response was
used. Existing permission-denied, inbox/bell, loading/error/empty, missing-ID picker and
domain-only administrator-notice evidence and their regression tests remain unchanged.

Telegram labels at the localhost base are not clickable anchors. Navigation acceptance
reuses #1583's reviewed trusted-HTTPS journeys for the unchanged provider/link path,
together with current source/destination existence and routing checks; this packet does
not claim a fresh Telegram localhost click. The old newest-twenty preview 404 observations
remain recorded rather than relabeled successful. Fixture parity uses the captured
previews and real receipts, and no elapsed hourly/daily soak, production capacity,
Microsoft SMTP, mobile matrix or screen-reader certification is claimed.

Only Teams/PagerDuty remain deferred. Issue ownership and the existing #1418/#1419
integration closures are unchanged. This PR keeps `Refs` where an issue's complete
cross-provider acceptance includes those deferrals; it does not close #1420 or #1576.

## Verified contact state matrix on 2026-10-18

The My profile surface #1412 added, captured from the console in Chromium against an API
serving PostgreSQL.

| Surface | Light | Dark |
| --- | --- | --- |
| No contacts yet | [Light](assets/ui/ws4-console/profile-contacts-empty-light.png) | [Dark](assets/ui/ws4-console/profile-contacts-empty-dark.png) |
| Added, pending verification, with the code form | [Light](assets/ui/ws4-console/profile-contact-added-light.png) | [Dark](assets/ui/ws4-console/profile-contact-added-dark.png) |
| An address the server rejects | [Light](assets/ui/ws4-console/profile-contact-invalid-light.png) | |
| Verification asked for with no relay configured | [Light](assets/ui/ws4-console/profile-contact-verify-unavailable-light.png) | |

Each state is the server's own answer. The added contact is a real row created through
`POST /api/v1/me/contacts`, the rejection is the API's validation of a malformed address,
and the unavailable state is what an operator sees when the deployment has no SMTP relay:
`RequestVerification` reports `email verification is unavailable` rather than queueing a
code nobody can receive.

The emailed code itself is not captured here. The operator relay is dialled through the
same SSRF guard as every other destination, so it refuses a loopback or private address,
and no public relay was available for this run. The code path is covered by
`TestContactVerificationUsesExistingSMTPTransport` and by the PostgreSQL verification
tests, which assert the single-use, per-user scoping of each challenge.

There is no permission-denied state for this surface: every signed-in person manages
their own contacts, and the routes derive the identity from the principal rather than
from anything the caller sends.
