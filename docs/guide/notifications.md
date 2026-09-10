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
```

The feature refuses to start without a stable vault key. Full webhook and Slack
URLs are encrypted because their paths may contain credentials. List and history
responses show only redacted destinations.

Email uses one relay controlled by the deployment operator. Configure
`SYNAPSE_NOTIFICATION_SMTP_HOST`, `SYNAPSE_NOTIFICATION_SMTP_PORT`,
`SYNAPSE_NOTIFICATION_SMTP_FROM`, and optional username/password. STARTTLS is
required by default. Tenant administrators choose recipients but cannot redirect
SMTP traffic to another relay.

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

The older `SYNAPSE_ALERT_WEBHOOK_URL` incident path remains available. When it is
configured, the worker suppresses the new `incident.created` producer so an
incident is not sent through both paths. Remove the legacy URL after equivalent
tenant rules and channels have been tested.
