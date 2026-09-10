# Notifications and webhooks

[Documentation home](README.md)

Synapse can route tenant events to signed HTTP webhooks, Slack incoming webhooks,
and email recipients. Delivery runs in `synapse-worker`; API requests and scans do
not wait for a remote service.

## Enable the framework

Both `synapse-api` and `synapse-worker` need the same PostgreSQL database and the
same 32-byte vault key:

```text
SYNAPSE_NOTIFICATIONS_ENABLED=true
SYNAPSE_DB_DSN=postgres://...
SYNAPSE_VAULT_MASTER_KEY=<64 hexadecimal characters or base64 for 32 bytes>
SYNAPSE_WORKER_PROFILE=all
```

The feature refuses to start without a stable vault key. Full webhook and Slack
URLs are encrypted because their paths may contain credentials. List and history
responses show only redacted destinations.

Email uses one relay controlled by the deployment operator. Configure
`SYNAPSE_NOTIFICATION_SMTP_HOST`, `SYNAPSE_NOTIFICATION_SMTP_PORT`,
`SYNAPSE_NOTIFICATION_SMTP_FROM`, and optional username/password. STARTTLS is
required by default. Tenant administrators choose recipients but cannot redirect
SMTP traffic to another relay.

Use the `all` worker profile; the specialized `lifecycle` and `integrations`
profiles do not consume notifications. The framework requires PostgreSQL and is
disabled by default. The development memory store does not emulate durable delivery.
`SYNAPSE_NOTIFICATION_SMTP_REQUIRE_TLS=false` is intended only for a controlled
development relay. Production relays must support verified STARTTLS.

## Configure routing

Open **Settings → Alerting**. Create a channel, test it, then create rules for one
of these events:

- `vulnerability_action.created`
- `scan.completed`
- `quality_gate.failed`
- `sla.approaching_deadline`
- `fleet.agent.offline`
- `incident.created`

Vulnerability and incident rules can set an inclusive severity floor. SLA rules
set a lead time (24 hours by default). Events created before the framework first
activates for a tenant are not replayed automatically.

Only tenant administrators (`PermAdminister`) can read or change these settings,
test channels, or inspect history. Channel type is immutable. Editing a URL or
HMAC key creates a new encrypted version; pending deliveries retain their original
version. Leaving both fields blank retains the secret. Email recipients are
snapshotted individually when an event is routed. Rule updates require the current
revision and apply to events that have not yet been routed.

### Source coverage and deduplication

| Event | Persistence boundary and stable source identity |
| --- | --- |
| Vulnerability action | Existing risk notification outbox ID; severity comes from the transition's immutable after-assessment. Requires the existing vulnerability notifications flag and dry-run disabled. This covers risk actions, not every raw scanner finding. |
| Scan completed | Successful persisted `scan_jobs` ID, including synchronous and asynchronous SCA scans with the job store configured. Failed/cancelled jobs and standalone CLI scans without persistence do not emit. |
| Quality gate failed | Finalized project analysis ID with `gate.Passed=false`; an engagement scan without a project analysis does not emit a gate event. |
| SLA approaching deadline | Current assessment ID, deadline and configured lead time. Only open/mitigating lifecycles with a future deadline and a non-exception tier qualify. Each lead time is delivered once. |
| Fleet agent offline | Agent ID and its last successful heartbeat timestamp. The freshness policy is `SYNAPSE_FLEET_STALE_AFTER`; polling is once per minute. Never-seen agents and agents already offline at initial activation do not page. A new heartbeat starts a new episode. |
| Incident created | Persisted correlated incident ID. Further detections attached to that incident do not create another notification. |

Scan, gate and incident records are captured in the same PostgreSQL transaction as
their authoritative write. The worker routes each captured record, creates deliveries
and durable jobs, and marks the record processed in one transaction. Risk outbox
handoff uses the same atomic boundary. Multiple matching rules collapse to one
delivery per channel (per recipient for email), with matched rule revisions retained.
No-match events are recorded and are not replayed when a rule is added later.

SLA and fleet relevance is checked again immediately before sending. Resolving an
SLA, changing its assessment/deadline, entering an exception, passing the deadline,
or receiving a new heartbeat cancels the old pending reminder.

Channel tests return `202` with a delivery ID. This means the test is durably
queued; inspect Delivery history for the final result. Disabling or deleting a
channel cancels pending deliveries. Existing in-flight requests cannot be recalled.

## Webhook contract

Signed webhooks receive JSON using schema version 1 and these headers:

```text
X-Synapse-Timestamp: <unix seconds>
X-Synapse-Signature: sha256=<HMAC-SHA256(timestamp + "." + exact body)>
X-Synapse-Event-ID: <stable event id>
X-Synapse-Delivery-ID: <stable destination delivery id>
```

Receivers should reject stale timestamps, compare signatures in constant time,
and deduplicate by delivery ID. A worker can crash after the receiver accepts a
request but before success is persisted, so HTTP delivery is at least once rather
than exactly once. Redirects and private, loopback, link-local, metadata, and
DNS-rebound destinations are blocked by the HTTP transport.

Slack uses a fixed Block Kit message and observes Slack's `429 Retry-After`.
Email creates one delivery per normalized recipient and uses a stable Message-ID.
SMTP acceptance means the relay accepted the message; it does not prove inbox delivery.

## Retry and cutover behavior

Network errors, HTTP 408/429/5xx, and SMTP 4xx responses retry with exponential
backoff and a one-hour cap. Other HTTP 4xx and SMTP 5xx responses are terminal.
Each attempt is recorded without response bodies or secret-bearing error strings.

The queue allows at most eight attempts, starting at ten seconds with deterministic
±10% jitter; valid `Retry-After` values are capped at one hour. Throttling reschedules
without consuming the attempt budget. An unfinished `started` attempt indicates an
unknown outcome after interruption. Acknowledged success is persisted before queue
completion, so replay of that committed success does not send again. Audit intents
are committed with results and retried independently of transport delivery.

Limits per tenant are 50 channels, 200 rules, and 10,000 pending/retrying deliveries
before another event fan-out is admitted (one admitted fan-out can add up to 2,500).
Sending is limited to ten attempts/second per tenant and one/second per channel,
across workers. Channel tests are limited to ten/minute/channel. API bodies are
limited to 32 KiB, event data to 16 KiB, email recipients to 50/channel, and history
pages to 200. Queue saturation rolls back source handoff for a later poll.

When API metrics are enabled, `synapse_notification_jobs{state="queued|claimed|failed|done"}`
exposes aggregate backlog and terminal jobs without tenant or destination labels.
`synapse_notification_queue_scrape_error` indicates unavailable statistics.

The older `SYNAPSE_ALERT_WEBHOOK_URL` incident path remains available. When it is
configured, the worker suppresses the new `incident.created` producer so an
incident is not sent through both paths. Remove the legacy URL after equivalent
tenant rules and channels have been tested.

Use the same legacy URL configuration on API and worker during cutover. Let the
worker drain incident source records while legacy delivery is active, then stop
the API and worker together, remove the legacy URL from both, and restart. Retained
unprocessed incident records from a period without a worker can otherwise be sent
after cutover. Initial activation is persisted per tenant; disabling the feature
pauses delivery rather than deleting retained records or resetting that cutoff.

### Secret rotation and retention

Use channel editing to rotate destinations and signing keys. Keep the previous
receiver key valid until its pending deliveries have completed. Channel deletion is
soft deletion; immutable event, attempt and encrypted version history remains.
This release has no automatic retention purge or manual redrive API. Monitor
database size and retain the vault master key with database backups. Replacing the
master key directly makes existing ciphertext unreadable; master-key rotation
requires an operator-controlled offline decrypt/re-encrypt migration of every retained
channel version using the same tenant/channel/version associated data.
