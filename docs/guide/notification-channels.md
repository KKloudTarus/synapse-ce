# Notification channels

[Documentation home](README.md) · Previous: [Configuration](configuration.md) · Next: [Notifications](notifications.md)

This guide covers operator controls and tenant-managed delivery settings. Enable
`SYNAPSE_NOTIFICATIONS_ENABLED` on the API and worker, use PostgreSQL, run
`synapse-worker`, and provide the same stable `SYNAPSE_VAULT_MASTER_KEY` to both
processes before enabling a tenant channel.

The provider-client acceptance matrix is still pending. This guide describes the
implemented contracts and configuration checks; it does not claim a live delivery
test against any provider.

## Operator controls

Use the same notification settings on the API and worker. The process environment
controls the fallback SMTP relay and the hosts that tenants may select:

| Variable | Purpose |
| --- | --- |
| `SYNAPSE_NOTIFICATION_SMTP_HOST`, `_PORT`, `_FROM`, `_USERNAME`, `_PASSWORD`, `_REQUIRE_TLS` | Operator SMTP relay. A tenant without its own relay uses this fallback. Keep passwords outside source control, logs, requests, and command history. |
| `SYNAPSE_NOTIFICATION_SMTP_ALLOWED_HOSTS` | Comma-separated exact DNS names for tenant-managed SMTP relays. An empty value permits no tenant relay. |
| `SYNAPSE_NOTIFICATION_CHAT_ALLOWED_HOSTS` | Comma-separated exact DNS names for tenant-managed Mattermost and Rocket.Chat webhooks. |
| `SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED` | Comma-separated channel types to disable globally. Set it identically on API and worker. |

Allowlist entries must be lowercase exact DNS names such as `smtp.example` or
`chat.example`. Wildcards, URLs, ports, paths, and IP addresses are rejected at
startup. Removing a host prevents a tenant from saving a new corresponding
destination. Self-hosted chat destinations are checked again at send time; tenant
SMTP relays are checked when settings are saved and when their sealed settings are
loaded for delivery.

The operator relay is independent of the tenant relay allowlist. It remains the
fallback while the tenant has no configured relay, which gives operators a rollback
path: clear a tenant relay and keep the operator relay configured.

## Tenant SMTP relay

An administrator manages a tenant relay through `GET` and `PUT
/api/v1/notifications/email-settings`. The write accepts one revisioned relay and
a complete set of approved recipient domains. Relay passwords, OAuth client secrets,
and refresh tokens are sealed immediately and are never returned by the read
endpoint or written to audit records.

Every tenant relay must use a host in
`SYNAPSE_NOTIFICATION_SMTP_ALLOWED_HOSTS`, a normalized `from` address, and port
`465` or `587`. TLS is mandatory: port 465 uses TLS from connection start and port
587 requires STARTTLS with certificate verification. Supply either an SMTP username
and password or one of the supported OAuth configurations.

Use placeholder values when preparing a request; put real values only in the
authenticated administrative request path:

```json
{
  "revision": 0,
  "relay": {
    "host": "smtp.example",
    "port": 587,
    "from": "notifications@example.com",
    "username": "<smtp-username>",
    "password": "<smtp-password>"
  },
  "domains": ["example.com"]
}
```

### Recipient-domain proof

Before a domain is added, publish this TXT record, substituting the tenant ID:

```text
_synapse-email.example.com. TXT "synapse-email-verification=<tenant-id>"
```

The service verifies this proof when adding a previously unapproved domain, then
caches the approved domain in tenant settings. It does not re-query DNS for every
send. Replacing `domains` with a set that omits a domain revokes that authorization
for future sends. At delivery time, each recipient must be either a verified
same-tenant contact or belong to an approved domain.

### Google Workspace / Gmail SMTP OAuth

Set `host` to `smtp.gmail.com`, choose port 465 or 587, and provide the sender in
`username`. The OAuth object requires `provider: "google"`, `client_id`,
`client_secret`, and a `refresh_token`; Synapse exchanges that refresh token at
Google's token endpoint and authenticates to SMTP with XOAUTH2. Configure the Gmail
OAuth consent and refresh-token grant for the mailbox before saving the relay.
Request the `https://mail.google.com/` scope for SMTP, as specified in Google's
[XOAUTH2 protocol](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol).

Google documents the `smtp.gmail.com` host, OAuth2/XOAUTH2, and the supported TLS
ports in its [IMAP and SMTP reference](https://developers.google.com/workspace/gmail/imap/imap-smtp).

```json
{
  "host": "smtp.gmail.com",
  "port": 587,
  "from": "notifications@example.com",
  "username": "notifications@example.com",
  "oauth": {
    "provider": "google",
    "client_id": "<google-client-id>",
    "client_secret": "<google-client-secret>",
    "refresh_token": "<google-refresh-token>"
  }
}
```

### Microsoft 365 SMTP OAuth

Set `host` to `smtp.office365.com`, choose port 587 with STARTTLS, and use the sender
mailbox address as `username`. The OAuth object requires `provider: "microsoft"`,
`client_id`, `client_secret`, and the Entra tenant UUID in `directory_id`. Synapse
uses the client-credentials grant with scope
`https://outlook.office365.com/.default` and authenticates to SMTP with XOAUTH2.

For this client-credentials path, register the Entra application with
`SMTP.SendAsApp`, register the corresponding Exchange service principal, grant the
application mailbox `FullAccess`, and grant it `SendAs` for the sender mailbox.
SMTP AUTH must also be enabled for the organization and mailbox. Microsoft documents
the [OAuth setup and Exchange permissions](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth/)
and the [SMTP AUTH enablement requirements](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission).
The [client SMTP submission guide](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365)
requires STARTTLS; Microsoft 365 does not support port 465 for this path.

```json
{
  "host": "smtp.office365.com",
  "port": 587,
  "from": "notifications@example.com",
  "username": "notifications@example.com",
  "oauth": {
    "provider": "microsoft",
    "client_id": "<microsoft-client-id>",
    "client_secret": "<microsoft-client-secret>",
    "directory_id": "<entra-tenant-uuid>"
  }
}
```

## Threading and tests

For a notification with a declared subject, delivery selects the earliest
successfully acknowledged remote reference for the same tenant, channel, pinned
channel-secret version, and subject. It orders by acknowledgement time and then
delivery ID, so later delivery has a deterministic anchor. Concurrent first sends
can both create a top-level message because neither has an earlier acknowledgement
yet. The event catalog currently declares no trusted closure state, so arbitrary
event data never causes closure or resolution to be inferred.

Telegram replies to the selected message ID and permits a missing parent to fall
back to a new message. Google Chat derives a stable thread key from the tenant,
channel, secret version, and subject, and asks Google Chat to fall back to a new
thread when necessary. Slack bot threading depends on PR #1570; deploy that change
with this implementation before expecting Slack replies to use the shared anchor.

A tenant administrator may request at most five channel tests per channel in a
rolling one-hour window. The limit counts test requests, not recipients, so a test
to an Email channel with several recipients still consumes one request.

## Operating and rolling back

Before rollout, rehearse index builds on representative event, delivery and
contact counts and set an appropriate DDL lock budget. These additive migrations
use ordinary indexes inside Goose transactions and may block writers while the
indexes build. Keep outbound notification processing paused during deployment:
apply the coordinated migrations, upgrade every notification worker, then upgrade
the API/UI and enable the providers. Older workers cannot decode the new channel
types and do not enforce the new send-time recipient policy.

For an immediate rollback, keep the current binaries and disable the affected
providers. If reverting binaries, quiesce deliveries and coordinate both API and
workers; remove new provider names from the disabled-provider variable before
starting older binaries, which reject unknown names. Preserve the additive schema
and sealed settings. Running the email migration's Down deletes relay/domain
state and is not the routine rollback procedure.

SMTP host approval grants network authority to that exact hostname, including
its private or loopback DNS addresses for a corporate relay. Metadata and other
special-purpose addresses remain blocked. TLS verifies the approved hostname;
operators must approve only relay hosts they trust. Self-hosted chat uses the
public-only tenant HTTP policy even when its hostname is allowlisted.

The Slack bot change reserves migration 0228. Include it before applying this
branch's migrations 0229–0231: Goose rejects an older missing migration after
the database has advanced past it. If these migrations are deployed first,
coordinate a new append-only migration number for the Slack change and verify
the combined order before rollout. This draft does not authorize that rollout.

During Slack integration, its `slackbotDriver.postSlack` payload must set
`thread_ts` from `NotificationWork.SubjectAnchor` when it is nonempty and retain
a top-level post otherwise. Keep the acknowledged Slack timestamp as `RemoteRef`
and add retry, deleted-parent, tenant/channel/version isolation and concurrent
follow-up contract tests on the combined branch.

Use `SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED` to stop a provider globally and pause
an individual channel in tenant settings when investigating delivery. Clearing a
tenant relay returns delivery to the configured operator SMTP fallback. Remove an
approved email domain to revoke future domain-based recipients; validated domains
remain cached until explicitly removed. Rotate channel credentials by updating the
channel, which pins new deliveries to the resulting secret version.
