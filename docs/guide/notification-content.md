# Notification content and capture rollout

[Notifications](notifications.md)

Messages use the event's stored, scrubbed template context, filtered to the lower
of the channel's data class and its engagement's external-notification policy.
Built-ins cover the seven routable events in English and Vietnamese for chat,
email, pager, and webhook families. Custom templates use the same engine.
Settings → Alerting exposes channel classes and raw webhook mode; an engagement's
Settings tab exposes `inherit`, `signal`, and `none` with revision conflict handling.

## Scan completion

New completed scans persist an immutable snapshot from the current execution
before cached findings enter a scan response. Severity counts exclude duplicates.
Later job status corrections retain that snapshot and its original completion time.
A correction to failed suppresses a pending success notification through the existing
delivery relevance check.
The baseline is the previous successful run of the same canonical target and
scan kind with an earlier `(finished_at, id)` ordering. PostgreSQL baseline search checks
the latest 128 successful jobs of that scan kind for a matching target; if none
matches in that window, delta remains unavailable. Comparison keys are bounded
to 10,000 findings; presentation contains at most 50 severity-ordered items within
the 16 KiB event context limit. Missing or incompatible baselines, partial coverage,
unstable identities, and truncated comparison keys make delta unavailable, rather
than reporting zero changes. Older runs without snapshots keep the original contract.

The `scan.completed` schema v2 adds signal-level counts and delta availability,
summary-level engagement name and target, and a detail-level `findings` list.
List items expose only `id`, `severity`, `title`, and `status`.

## Webhook contract

Default webhooks send a versioned, class-filtered envelope:

```json
{
  "version": "synapse.notification.v1",
  "event": {
    "id": "event-id", "type": "scan.completed", "schema_version": 2,
    "occurred_at": "2026-10-01T08:00:00Z"
  },
  "data": {
    "vars": {"event_type": "scan.completed", "scan_kind": "git", "total_count": "3"}
  },
  "links": [{"label": "Open scan", "url": "https://console.example/engagements/e1/scanruns#scan-s1"}]
}
```

`data.vars` contains declared string values. `data.lists` is present only when a
declared list is available at the effective class. Webhook times remain RFC 3339
UTC. `X-Synapse-Signature` remains `sha256=` plus HMAC-SHA256 of
`<X-Synapse-Timestamp>.<exact request body>`; verify received bytes before parsing
JSON and enforce the receiver's replay window.

`links` is optional and contains only routes created by the trusted console-link builder. It is
omitted when the public console URL is unset or the event has no matching console route.

An administrator can enable `raw_event` on a `detail` webhook for a receiver that
requires the original event envelope. This is audited and mutually exclusive
with `custom_body`. An integration administrator can disable it but cannot enable
it. An engagement capped at `signal` sends the filtered envelope even on a raw
channel; `none` suppresses delivery. Update receivers before deploying the worker,
or opt in explicitly where raw delivery is required.

Email renders text and HTML from the same Markdown document in a code-owned
layout. Values are escaped, links use the trusted console builder, and no remote
images or resources are loaded. Vietnamese subjects use MIME encoding and CR/LF
cannot create headers. Tenant channel email includes `List-Unsubscribe` only when
the operator configures `SYNAPSE_NOTIFICATION_UNSUBSCRIBE_URL` as an HTTPS workflow
that can remove recipients from channel distributions, including recipients without
Synapse accounts. Synapse does not append recipient addresses to that URL and does
not advertise a one-click action. Personal inbox preferences do not control tenant
channel recipients. Without a configured unsubscribe workflow the header is omitted;
without `SYNAPSE_PUBLIC_BASE_URL`, console deep links are omitted.
Validate the operator workflow and appearance in dedicated real-client test accounts.

## Identity capture rollout

Migrations install mode `legacy`. Runtime database roles can read the operator-owned
capture policy but cannot change it. Use the existing migration credential:

Before applying the scan snapshot migration, rehearse it against representative
`scan_jobs` history in staging. Its transaction holds an `ACCESS EXCLUSIVE` table
lock through the ordinary predecessor index build, so reads and writes can pause
for the entire build. Schedule a maintenance window, pause scan admission and drain
active scan writers before running `synapse-migrate`. Keep the migration within its
two-minute deadline; if the rehearsal exceeds that budget, plan an online index
migration before releasing this build.

If migration fails or times out, keep traffic paused while confirming that its
transaction has ended and checking the Goose version, snapshot column and index.
The snapshot migration is transactional; its failed changes roll back while earlier
completed migrations remain applied. Retry only after resolving the blocking session
or capacity problem. Start the new services only after the migration command succeeds.

1. Run `synapse-migrate`, then deploy this API and worker release. Confirm every
   notification worker has the capable projector.
2. Run `synapse-migrate --notification-capture-mode identity`. The command waits
   for in-flight captures before switching and reports pending identity records.
3. Verify new scan, quality-gate, and incident records have `capture_version=2`
   and empty `data`, while projected events have scrubbed contexts. Monitor
   projection errors, pending records, and delivery attempts.

An older worker cannot publish or mark identity records processed or quarantined:
SQLSTATE `55000` leaves the record pending. The capable projector sets a
transaction-local marker after source hydration. This guard prevents silent
consumption; the operator still checks the deployed worker fleet.

An identity source that cannot be hydrated stays pending and rolls back that tenant's
projection transaction. Inspect `notification source poll failed` logs and pending
identity records, then restore the source facts or deploy a capable projector. Retry
with that worker; do not mark the source processed manually. Legacy capture retains
its existing invalid-source quarantine path.

The mode command holds the capture barrier while counting pending records per
tenant and shares the migration command's two-minute deadline. A timeout rolls
the switch back. Measure this pause with the deployment's tenant count and database
latency in staging before cutover; capture resumes when the command commits.

To roll back, run `synapse-migrate --notification-capture-mode legacy`, keep a
capable worker running until the reported pending identity count reaches zero,
then replace workers. Switching mode preserves captured records and event history.
Before replacing notification workers with a release that predates the filtered
webhook contract, disable webhook channels. That older sender uses the raw event
envelope and does not enforce the new `raw_event` opt-in. Keep a capable notification
worker when class-filtered webhook disclosure is required.
The capture migration refuses downgrade while identity mode or pending identity
records remain. Do not remove scan snapshot columns while stored snapshots exist.
