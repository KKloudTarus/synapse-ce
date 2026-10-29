# Notification event live validation

This ledger separates source-operation evidence from provider transport tests and
from the remaining client acceptance matrix. It records the local run on
2026-10-13. Provider credentials and repeatable operation state remain in the
operator's private runtime directory; they are not part of this repository.
The [functional follow-up](#functional-follow-up) records later operational proof
and the remaining environment gaps without rewriting these historical observations.

## Environment and operations

The isolated Compose project runs PostgreSQL 17, MinIO, the API, the production
web console, and a worker with `SYNAPSE_WORKER_PROFILE=notifications`. Published
ports bind to loopback. The API and worker share the application database and
vault key; the application role cannot bypass RLS. Notifications and SLA are
enabled, and optional paid model calls are disabled. A private Compose override
adds the notification worker; the base full-stack Compose file does not start one.

Source operations use the local HTTP API. No notification event, delivery,
source snapshot, or lifecycle row was inserted manually. The operation harness
persists creation intent and recovers an uncertain response before retrying a
mutation. Its finding pass creates one manual finding, rejects a stale version
with HTTP 409, changes status, and records a still-vulnerable retest. The retest
also creates a second status-change event. Bulk SCA imports deliberately do not
emit `finding.created` for every advisory finding.

Start and wait for the notification poller before producing test operations.
Four operations submitted before tenant activation produced no captures or
deliveries, as expected; a fresh finding was used after activation. That check is
recorded in [activation-receipt.json](assets/ui/notification-events/live/activation-receipt.json).

For recovery, the worker was stopped after activation, four finding source
operations committed, and the API was killed before projection. PostgreSQL
retained all four pending version-3 snapshots. Restarting the API and worker
projected each once and delivered the historical open/triage/confirmed facts even
though the current finding had already advanced. Repeating the completed finding
operation pass and restarting the worker did not add another source or delivery.

A scan against a missing owned local fixture produced `scan.failed`, including
an unavailable finding count rather than a fabricated zero. A separate real
dependency scan used a read-only Docker volume containing a package manifest and
lock file. It produced three advisory findings and SLA assessments. An earlier
empty bind-mount scan produced no components and is not used as scan evidence.

A short positive SLA policy let those three findings cross their actual
remediation deadlines. Risk acceptance for the high-severity finding was then
created through the lifecycle API with a future expiry. Warning, expiry and the
next breach episode were observed using the real clock.

## Delivery and boundary evidence

Each main event instance fans out to 20 configured channels: Slack, Google Chat,
Telegram, Discord and a webhook receiver, each in English/Vietnamese and
signal/detail configurations. The 12 main source instances produced 240 logical
delivery rows. Of these, 231 were delivered in one attempt with HTTP 200. The
remaining nine were warnings cancelled as `source_no_longer_relevant` when their
acceptance expired; they made no provider request. No main row remained pending,
retrying or dead-lettered.

The warning's event time is 04:17:28 UTC. Eleven warnings arrived before expiry;
nine queued warnings were suppressed at the 04:18:28 UTC boundary. Expiration and
the new SLA breach both retain that exact boundary as their event time, even
though the next scheduler poll projected them at 04:19:21 UTC. All 20 expiration
and all 20 new-breach deliveries completed. Configure warning lead time to cover
the poll interval and expected delivery backlog; a one-minute lead can be too
short for a large fan-out.

An additional finding, restricted to four Discord channels, verified the repaired
severity color on the rebuilt worker. A second finding, restricted to 16 chat
channels, verified typed severity badges on Slack, Google Chat and Telegram and
retained Discord's native color. Together with the main run, these checks produced
260 logical rows: 251 delivered in one successful attempt and nine stale warnings
cancelled before any request. The
[source/delivery receipt](assets/ui/notification-events/live/source-delivery-receipt.json)
contains event identities, capture version, source projection time, fact equality,
logical delivery identities and attempts. It omits recipients and destination
URLs. Provider message references are retained where available; a generic
webhook can acknowledge delivery without returning a message reference.

The parsed receiver body is saved separately as
[received expiration JSON](assets/ui/notification-events/live/webhook-risk-expired-received.json).
The [signature receipt](assets/ui/notification-events/live/webhook-signature-receipt.json)
confirms HMAC-SHA256 against the receiver's actual raw body and timestamp header,
without exposing its key.

A second tenant could not read the first tenant's engagement, channel or delivery
(HTTP 404) and listed no channels. See the
[tenant receipt](assets/ui/notification-events/live/tenant-isolation-receipt.json)
and the delivery receipt's foreign-tenant check. Disabled notifications, a missing
vault key and an invalid vault key each stopped the real notification worker
before its claim loop; see the
[startup receipt](assets/ui/notification-events/live/startup-guards-receipt.json).
The live worker metrics endpoint remained available after composition and restart.

## Client inspection

Client screenshots contain synthetic test content and exclude credentials,
receiver URLs and unrelated account conversations.

| Client | Current evidence |
| --- | --- |
| Slack | Current finding titles have a high-severity orange badge and the stored severity label in EN/VI, with signal/detail text. [EN](assets/ui/notification-events/live/slack-finding-created-en-light.png), [VI](assets/ui/notification-events/live/slack-finding-created-vi-light.png), [SLA](assets/ui/notification-events/live/slack-sla-vi-en-light-desktop.png). Lifecycle replies use the existing thread. |
| Google Chat | Current EN/VI finding cards show the orange badge, severity label and class-specific facts. [Finding](assets/ui/notification-events/live/google-chat-finding-created-en-vi-light.png), [SLA](assets/ui/notification-events/live/google-chat-sla-vi-en-light-desktop.png), [lifecycle thread](assets/ui/notification-events/live/google-chat-risk-created-expired-thread-en-light.png). |
| Telegram | Current EN/VI finding messages show an orange badge, intact diacritics and signal/detail facts. [Finding](assets/ui/notification-events/live/telegram-finding-created-en-vi-light.png), [risk acceptance](assets/ui/notification-events/live/telegram-risk-created-en-vi-light-desktop.png). Lifecycle messages retain the SLA reply relationship. |
| Discord | Actual finding messages show the severity label and native high-severity color with signal/detail content in both themes. [Dark](assets/ui/notification-events/live/discord-finding-severity-en-vi-dark-desktop.png), [light](assets/ui/notification-events/live/discord-finding-severity-en-vi-light-desktop.png). The original dark preference was restored. |
| Webhook receiver | Parsed signal payload with the exact expiration time and severity; raw-body signature verified. [Screenshot](assets/ui/notification-events/live/webhook-risk-expired-signal-received.png). |

These images prove the views they show. They do not constitute the complete
event-by-client, locale, class and theme acceptance matrix. The browser viewport
override did not change the extension tab's actual viewport, so this run makes no
mobile layout claim.

## Remaining acceptance prerequisites

The maintainer deferred Teams and PagerDuty live acceptance to
[the EPIC](https://github.com/KKloudTarus/synapse-ce/issues/1327); they no longer
block code-review readiness for this PR. The EPIC retains unchecked follow-up items.

Gmail has real receipt evidence from the earlier channel acceptance run: ten
SMTP/XOAUTH2 self-mail acceptances and native inbox/body inspection, recorded in
[the provider receipt](assets/ui/notification-channels/live/provider-retest-receipt.json)
and [Gmail capture](assets/ui/notification-channels/live/gmail-builtins-ten-messages-desktop.jpg).
Its coverage is the five earlier scenarios in that receipt, not all eleven new
events. The grant was revoked after that run. A fresh B03 email replay still needs
an active sender configuration; Outlook remains unverified.

The existing JSM test team has been reused with a dedicated events integration
and on-call notifications disabled. Current source-operation evidence is recorded
below. The maintainer also accepts HTTP for the dedicated Mattermost/Rocket.Chat
fixtures. That test exception does not change production HTTPS/SSRF policies.

DAST and recon execution need a hardened Linux scanner environment with the
required kernel/sandbox capabilities. CSPM additionally needs authorized test
cloud credentials. Their producer, schema and recovery tests are present, but
this notification worker does not execute those jobs and this run does not claim
live scanner completion for them.

The initial run left `SYNAPSE_PUBLIC_BASE_URL` unset and omitted console links.
The follow-up below supplies HTTPS and verifies one real client-to-finding path.
Remaining client themes, locales, classes, event types and the rest of the
link-click matrix keep external acceptance open. The PR references the event
issues without closing them.

## Ready-gate follow-up

On 2026-10-13, the branch still contained the current main commit. The local
worktree-bound technical gate validated. GitHub's Actions permissions endpoint
reported `enabled: false`; no Actions run existed for this branch, and the PR
reported only GitGuardian success. The absence of CI runs is not a CI pass.

Docker initially refused startup with a WSL-update precondition. `wsl --update`
reported the installed version current; restarting Docker Desktop and running the
private stack launcher restored all five services to healthy without resetting
volumes or database state.

A tailnet-only Tailscale Serve HTTPS origin now proxies the console. Both API and
worker use that origin as `SYNAPSE_PUBLIC_BASE_URL`. Browser certificate validation
remained enabled. A fresh manual finding through the API produced 16 successful
deliveries across Slack, Google Chat, Telegram and Discord, with both locales and
both data classes. These are additional to the earlier 260-row receipt, not a
replacement for it. See the [follow-up receipt](assets/ui/notification-events/live/https-link-receipt.json).

The real Discord message exposed an Open finding link. Clicking it and accepting
Discord's ordinary leaving-site prompt opened the HTTPS console at the exact
engagement and finding fragment. Development-token login in the new tab preserved
the destination; the matching finding row expanded automatically. The captures
show the [message link](assets/ui/notification-events/live/discord-finding-https-link.png)
and the [expanded destination](assets/ui/notification-events/live/console-finding-https-destination.png).
This proves that finding path from Discord; it does not establish clicks from the
other clients or links for every event type.

| Remaining condition | Evidence needed to clear it |
| --- | --- |
| Repository CI | GitHub Actions enabled under the repository's intended policy, then applicable checks passing on the PR head. Local checks remain recorded separately. |
| Provider acceptance | Teams/PagerDuty deferred to the EPIC; Gmail prior receipt linked with its recorded coverage; current JSM and HTTP fixture checks below. Fresh B03 email replay and Outlook remain unverified. |
| Scanner operations | Hardened Linux execution for DAST/recon and authorized cloud test credentials for CSPM. |
| Rendered acceptance | Per-event, client, EN/VI, signal/detail and applicable theme captures, with the required link clicks and reviewer inspection. |

The technical gate establishes readiness for code review. Full leaf/EPIC
acceptance remains separate, following the disposition used in PR #1572. The
referenced issues remain open where their full client matrix is incomplete.

## JSM source-operation follow-up

The existing Synapse Notification Test team now has a dedicated events integration.
On-call notifications are disabled; the native activity log confirms suppression.
One real API finding creation, two status changes and a retest produced 16 logical
deliveries across four EN/VI and configured signal/detail channels. JSM caps both
configured classes at signal. All deliveries completed with provider references;
the four subject/channel aliases retained four alerts, each receiving four event
occurrences. Replaying the completed operation harness left 16 logical deliveries.

Each mutation's accepted request is persisted and confirmed on a later attempt;
32 recorded attempts returned HTTP 202 across the 16 completed deliveries. The
[receipt](assets/ui/notification-events/live/jsm-source-delivery-receipt.json)
records logical identities, references and status codes without credentials.

Native JSM captures show [English](assets/ui/notification-events/live/jsm-finding-created-en-light.png),
[Vietnamese](assets/ui/notification-events/live/jsm-finding-created-vi-light.png)
and [follow-up activity](assets/ui/notification-events/live/jsm-finding-followups-vi-light.png).
High severity maps to P2. Clicking the alert's console link, then signing in with
the local development token, preserves the exact finding fragment and expands
[the matching finding](assets/ui/notification-events/live/jsm-finding-console-destination.png).
These checks establish the three finding event types; other JSM event types and
the complete client-theme matrix remain separate acceptance work.

## Self-hosted HTTP fixture follow-up

The final controlled replay accepted 88 posts with HTTP 200: all eleven event
contracts, EN/VI, signal/detail and both Mattermost/Rocket.Chat. It uses the
current built-in renderer, formatter and sender with synthetic EventSpec
snapshots. An exact-host test transport maps the two approved HTTPS fixture
origins to the existing local HTTP services. Production code and its HTTPS/SSRF
validation are unchanged. Existing incoming webhooks are reused.

The [receipt](assets/ui/notification-events/live/self-hosted-http-receipt.json)
identifies the source commit, harness digest and every accepted combination.
It records only the final replay; two earlier exploratory batches remain in the
test channels but are excluded from its 88-post count. This is renderer/sender
acceptance, not source-operation, outbox, worker, idempotency or deep-link proof.
The fixed fixture clock and synthetic destinations do not establish real
lifecycle timing or clickable console navigation.

Native captures show [English findings](assets/ui/notification-events/live/mattermost-finding-en-dark.png)
and [Vietnamese risk lifecycle](assets/ui/notification-events/live/mattermost-risk-lifecycle-vi-dark.png)
in Mattermost, and [Vietnamese expiration](assets/ui/notification-events/live/rocket-chat-risk-expired-vi-light.png)
in Rocket.Chat. The screenshots establish those views; the other combinations
have transport receipts, not a complete native theme/locale capture matrix.

## Functional follow-up

On 2026-10-29, representative functional journeys completed the remaining
creation/promotion, retest, stale-scan/dead-letter and SLA reminder/cap source
coverage. The maintainer requested functional proof without another theme matrix.
Existing renderer, tenant, recovery and hostile-input regressions remain accepted;
this criterion does not waive runtime authorization or evidence integrity.
[Tracker #1576](https://github.com/KKloudTarus/synapse-ce/issues/1576) still owns the
external environments and execution paths listed below.

| Journey | Observed result and scope |
| --- | --- |
| Retest | All three outcomes, their status transitions and stale-version denial, followed by real Slack receipts and finding navigation. [Receipt](https://github.com/KKloudTarus/synapse-ce/issues/1576#issuecomment-6487881346). |
| SLA | Production assessment and source polling with a controlled clock produced ordinal 0 and one capped reminder; PostgreSQL and Slack delivery were real. This is not a multiday soak. [Receipt](https://github.com/KKloudTarus/synapse-ce/issues/1576#issuecomment-6487975155). |
| Stale scan | A worker running the real pipeline was killed with SIGKILL. After the wall-clock stale threshold, a maintenance helper invoked production `SweepStaleScans`; normal worker redelivery retained one failed source and delivery. Periodic scheduler timing is not claimed. [Receipt](https://github.com/KKloudTarus/synapse-ce/issues/1576#issuecomment-6488224328). |
| Dead-letter | Three lease acquisition faults scoped to one disposable scan exhausted the real queue. A fourth acquisition let the terminal handler persist `failed/dead-letter`; one Slack delivery returned HTTP 200. The trigger, function and sequence were removed. Engines had not run, so the console has unknown coverage and no completed scan-run row. [Receipt](https://github.com/KKloudTarus/synapse-ce/issues/1576#issuecomment-6488733441). |
| Creation/promotion | A sandboxed CGO Python parser and production taint coordinator proposed a CWE-78 claim. An independent static assessment was submitted through the existing operator-authorized verification API. A sealed verdict produced one SAST finding and one Slack delivery; replay did not duplicate them. This is a source-only static journey, not a complete SCA job or runtime exploit. [Receipt](https://github.com/KKloudTarus/synapse-ce/issues/1576#issuecomment-6488863842). |
| Telegram threading | Real same-subject replies, deleted-parent fallback, and subject/channel/local credential-version isolation produced eight successful deliveries. Credential-version testing reused the existing bot credential; no cloud rotation is claimed. [Receipt](https://github.com/KKloudTarus/synapse-ce/issues/1576#issuecomment-6488361514). |
| Local SMTP relay | Admin UI configure-465, replace-with-587 and unset-only fallback produced four actual SMTP messages. Certificate verification, rejected host/port, stale revision and safe settings/audit were checked; a Mailpit link opened the finding. This proves local relay behavior, not Gmail/Outlook, XOAUTH2 or mobile-client acceptance. [Receipt](https://github.com/KKloudTarus/synapse-ce/issues/1576#issuecomment-6488527239). |
| JSM lifecycle | Finding transitions created and closed real alerts; reopening created a distinct episode. Restart and same-version channel restoration resumed the original asynchronous request. The paired closure implementation shipped in [#1625](https://github.com/KKloudTarus/synapse-ce/pull/1625); live PagerDuty remains excluded. |

The [tenant relay rollout receipt](assets/ui/notification-events/live/tenant-relay-rollout.json)
adds an actual migrate-first rehearsal from schema 231 to 234: old API/worker, feature runtime with
configured relay, verified TLS/AUTH SMTP delivery and history, feature restart, old-binary rollback
on the expanded schema, feature restoration and a second delivery. Legacy mappings and relay data
remained intact; the runtime role had neither superuser nor RLS bypass. This uses the exact historical
old and feature commits recorded in the receipt, rather than attributing that run to later code.

Synthetic DDL runs measured 28.560 ms at 10,000 contacts, 107.583 ms at 100,000 and 19,214.846 ms
at 1,000,000. A conflicting lock caused atomic rollback with a 500 ms per-lock timeout; total abort
time reached 2,611.443 ms at 1,000,000 because the timeout is not a total migration deadline.
These local measurements inform a maintenance window, not a production capacity or zero-downtime
claim. The largest run had only two successful writer samples. Rollback keeps the expanded schema;
running Down would delete relay/domain data. Both disposable rehearsals cleaned up their containers
and networks.

The dead-letter and promotion runtime used source
`e77c95e3ac7dd5d8167b3d789d04edda1ab0e92d`, merged by #1625. Their
[correlated receipt](assets/ui/notification-events/live/functional-followup.json)
records immutable source/event equality, delivery identities and image hashes.
The promotion finding retains severity `unknown`; its verification score does not
invent severity. The independent assessment was static, not a claim of human
review or the external LLM auto-verifier.

![Dead-letter console before engine execution](assets/ui/notification-events/live/scan-deadletter-console.png)

![Promoted SAST finding after restart](assets/ui/notification-events/live/promoted-finding-console.png)

The isolated PostgreSQL, local object store, mailboxes and sealed settings are
retained. All ten services were stopped and resumed successfully: the signed
three-link promotion evidence chain kept its head, and the sealed fixture
artifact downloaded byte-for-byte unchanged. The services were then stopped to
release resources. The private resume command derives current container addresses
and uses retained configuration; no manual provider setup is needed for these
completed journeys. Older in-memory artifacts are not restored by adding the
object store.

### Navigation equivalence

The [eight lifecycle manifests](notification-lifecycle-events.md#local-evidence-artifacts)
retain 704 reviewed cells and 48 clicked destination groups. Each provider covers
approval, engagement, evidence, finding, incident and response route families.
Those are destination proofs, not a claim that every event or screenshot was
clicked. New source operations add actual finding clicks for retest, SLA,
promotion and local SMTP, scan-error navigation for recovery/dead-letter, and an
evidence-failure engagement view. Mattermost and Rocket.Chat also have integrated
finding clicks. Reuse is limited to the same destination behavior; synthetic
response payloads still do not prove a governed host response operation.

### PostgreSQL refresh

The full PostgreSQL package ran on a fresh isolated database at
`cc6e25977340badb9ba194f585b4f42bb27ca828`, which contains B05 merge
`b88812e15fce7c88604bc735872532fe5cae75f3`. Command:
`go test -count=1 -timeout=45m -json ./internal/infrastructure/persistence/postgres -run .`.
It exited 0 after 2,079.495 seconds with 1,215 pass events and four skips.
`TestResponseHaltWriterRoleIsolation` then passed separately at the same revision
with distinct runtime and halt-writer roles. The other skips were two opt-in scale
benchmarks and the interactive assessment UI worker. The earlier timeout stays
failed evidence; no hosted Actions result is claimed.

### Governed process response

The governed host-response environment was subsequently completed on 2026-10-29.
Two retained, isolated Linux KVM guests supplied a real executor and a distinct
observer. A consultant submitted the exact process fingerprint and an operator
recorded the authorized decisions. Stop reached `verified_succeeded`; the separately
approved best-effort restart reached `rolled_back` with verification `succeeded`.
The replacement used the pinned executable, cwd and UID, with a different process
entity ID. The reversal receipt keeps the original exit timestamp before the
reversal window and binds the exact child's successful exec event.

The [correlated receipt](assets/ui/notification-events/live/governed-process-response.json)
records component binary hashes, changed-source hashes, both sealed verification
records and three immutable source/event pairs. `applied`, `verified` and `reverted`
each reached Slack through the durable worker once with HTTP 200. The Vietnamese
[native receipt](assets/ui/notification-events/live/process-confirmed-slack-native.png)
was inspected; its Open response link opened the HTTPS console and, after sign-in,
showed [Reverted / succeeded](assets/ui/notification-events/live/process-confirmed-native-link-console.png).
The later failed message belongs to a separate wrong-asset diagnostic request that
was rejected at human approval, not the verified operation. Out-of-scope admission,
wildcards and a consultant's approval attempt returned 403, 400 and 403 respectively.

This rehearsal used a five-minute command/verification budget and the normal
two-minute work lease. Earlier failed and timed-out attempts remain unchanged.
The observer was upgraded during reversal; the executor stayed running to preserve
its pinned restart descriptors. This proves the governed local operation and Slack
journey, not production capacity, other operating systems or deferred clients.

### Restored Gmail SMTP

On 2026-10-30 (Asia/Bangkok), the retained identity sandbox delivered four
self-mails through Google OAuth SMTP: an initial channel test, one real manual
finding in EN/VI, and a channel test after worker restart. Each delivery has one
SMTP 250 attempt and exactly one matching Message-ID in the Gmail Inbox. The
[receipt](assets/ui/notification-events/live/gmail-smtp-live.json) binds the
finding's immutable source record, projected event, deliveries and actual runtime
image digests. Received subject, plain text and HTML match the stored-event
preview for both source messages.

The [English](assets/ui/notification-events/live/gmail-source-en.png) and
[Vietnamese](assets/ui/notification-events/live/gmail-source-vi.png) native body
crops show the red critical label, intact Vietnamese title and literal hostile
strings. The full URL is defanged and the only HTML anchor is the generated
console link. A native Gmail click, repeated after normal sign-in, opened the
[exact finding](assets/ui/notification-events/live/gmail-finding-console.png)
under the existing readonly membership. The unauthenticated sign-in returned to
Dashboard; automatic deep-link restoration is not claimed.

The existing personal project supplied a new Desktop client and an explicitly
approved self-test grant. No project, API enablement, compute or billing change
was made. Client material and tokens are encrypted locally; mailbox headers and
raw MIME stay private. The operator resume command was exercised without fresh
consent or enrollment. The test rule and channels are disabled and the worker is
parked, with configuration retained. This Testing grant expires around
2026-11-05 16:55 UTC; encrypted storage does not remove the provider's expiry.
This is representative current SMTP/source proof, not every event/client cell
or Microsoft SMTP acceptance. Historical receipts keep their original scope.

### Remaining environments

Four service setups remain unavailable after the Gmail restoration above. The
direct environment audit on 2026-10-28 recorded five. This is a setup count,
not a count of all untested acceptance cells; SharePoint and OneDrive Business
are grouped together.
The Google Chat personal session was rechecked on 2026-10-29; no space or
webhook was created. Google's [documented webhook prerequisites](https://developers.google.com/workspace/chat/quickstart/webhooks)
require an eligible Workspace account and organization permission. The other
setup rows retain their original audit date.

| Setup | Verified gap |
| --- | --- |
| Teams | No authorized work tenant with a usable test bot and conversation; the current personal account was rejected. |
| Microsoft SMTP / Outlook | No authorized Exchange mailbox and SMTP entitlement verified. Entra Free sign-in does not provide a mailbox. |
| SharePoint / OneDrive Business | No Business site/drive and restricted-reader setup verified. An Entra app alone is insufficient. |
| Google Chat | No current eligible configured space/webhook in the personal session. Historical receipts remain valid. |

Okta, Google Workspace identity, PingOne and PagerDuty are intentionally excluded
by the maintainer and are not counted in those four. Google Workspace identity
and Gmail SMTP are separate integrations.

Two execution environment groups remain unproved: governed DAST/recon needs an
authorized target and egress/grant authority; CSPM needs authorized test-cloud
credentials. Strict local sandbox conformance passed, but that does not establish
these remaining execution prerequisites. Custody failure was exercised in a disposable
chain and reporting failed closed; retained audit/evidence history was untouched.
The [custody receipt](assets/ui/notification-events/live/functional-followup.json)
records the verifier transition, HTTP 400 report denial and one delivered event.
These source rehearsals reuse retained sandbox configuration with optional paid
model calls disabled. Provider subscription and billing status are separate from
delivery proof; verify them before resuming a cloud destination.
