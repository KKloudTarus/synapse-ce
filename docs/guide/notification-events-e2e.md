# Notification event live validation

This ledger separates source-operation evidence from provider transport tests and
from the remaining client acceptance matrix. It records the local run on
2026-10-13. Provider credentials and repeatable operation state remain in the
operator's private runtime directory; they are not part of this repository.

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

Teams needs a dedicated Microsoft test destination and working Workflows or bot
credentials. Gmail and Outlook need working SMTP/OAuth test credentials; earlier
provider proofs are not evidence for this run. PagerDuty needs a test service and
routing key. The dedicated JSM test team has no current integration key.
Mattermost and Rocket.Chat local HTTP fixtures need a trusted HTTPS origin before
the production sender can use them. No transport or certificate guard was relaxed
to turn a local fixture into a provider proof.

DAST and recon execution need a hardened Linux scanner environment with the
required kernel/sandbox capabilities. CSPM additionally needs authorized test
cloud credentials. Their producer, schema and recovery tests are present, but
this notification worker does not execute those jobs and this run does not claim
live scanner completion for them.

The initial run left `SYNAPSE_PUBLIC_BASE_URL` unset and omitted console links.
The follow-up below supplies HTTPS and verifies one real client-to-finding path.
Remaining client themes, locales, classes, event types and the rest of the
link-click matrix keep external acceptance open. The PR stays draft and references
the event issues without closing them.

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
| Missing provider destinations | Working dedicated Teams, Gmail/Outlook, PagerDuty and JSM test configuration; trusted HTTPS for the local Mattermost/Rocket.Chat fixtures. |
| Scanner operations | Hardened Linux execution for DAST/recon and authorized cloud test credentials for CSPM. |
| Rendered acceptance | Per-event, client, EN/VI, signal/detail and applicable theme captures, with the required link clicks and reviewer inspection. |

The implementation gate passes, but the plan's full acceptance gate remains open.
No issue is closed and the PR is not marked ready on the strength of partial client
evidence.
