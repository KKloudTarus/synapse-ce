# Notification channels

[Documentation home](README.md) · Previous: [Configuration](configuration.md) · Next: [Notifications](notifications.md)

This guide covers operator controls and tenant-managed delivery settings. Enable
`SYNAPSE_NOTIFICATIONS_ENABLED` on the API and worker, use PostgreSQL, run
`synapse-worker`, and provide the same stable `SYNAPSE_VAULT_MASTER_KEY` to both
processes before enabling a tenant channel.

See the [notification event ledger](notification-events-e2e.md) for source-to-client
receipts and the remaining provider prerequisites.

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

JSM acknowledges creates and closes asynchronously. A successful HTTP acceptance
stores an internal request handle with the retry transition; subsequent worker
attempts check that request rather than creating another alert. A status that is
not yet visible (`404`) or remains pending is retryable. Only a confirmed success
records the acknowledged alert reference. Quiesce JSM workers before reverting
the provider-request migration: its rollback drops pending request handles.

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

Microsoft's [revised SMTP AUTH Basic authentication schedule](https://techcommunity.microsoft.com/blog/exchange/updated-exchange-online-smtp-auth-basic-authentication-deprecation-timeline/4489835)
was checked on 2026-10-29. It leaves Basic authentication unchanged through
December 2026, then turns it off by default for existing tenants at month end.
Tenants created after December 2026 use OAuth by default. Microsoft plans to
announce the final Basic authentication removal date in the second half of 2027;
that is an announcement milestone, not the removal date itself. These milestones
concern Basic authentication, not Synapse's OAuth/XOAUTH2 flow. The mailbox,
Exchange grants and SMTP AUTH policy above still require independent verification.

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

## Google Chat webhook prerequisites

Google's [incoming webhook quickstart](https://developers.google.com/workspace/chat/quickstart/webhooks)
requires a Business or Enterprise Workspace account whose organization permits
incoming webhooks, plus a destination space. Access to the personal Gmail Chat UI
or the ability to create a personal space does not establish those prerequisites.
Check the authorized account and space before creating a webhook credential.

## Threading and tests

For a notification with a declared subject, delivery selects the earliest
successfully acknowledged remote reference for the same tenant, channel, pinned
channel-secret version, and subject. It orders by acknowledgement time and then
delivery ID, so later delivery has a deterministic anchor. Concurrent first sends
can both create a top-level message because neither has an earlier acknowledgement
yet. This chat-thread behavior is separate from pager lifecycle admission.

For newly captured finding and incident events, pagers use a source episode and
revision recorded in the business transaction. Findings end an episode at
`remediated` or `false_positive`; incidents end it at `resolved` or `closed`.
Moving from a terminal state back to an active state starts another episode and
another provider alias. An incident disposition does not close an alert. Historical
events without this metadata retain their legacy behavior; event JSON and template
text cannot request closure.

Each channel uses one alert alias per episode and serializes the matched updates
sent to that alert. A terminal event closes the admitted alert after submitted
updates have settled, even if the rule only matches creation.
A terminal event received before an unsent trigger suppresses that trigger. JSM
request handles survive worker lease expiry and resume through status reads. A
mutation whose outcome is unknown remains blocked instead of being sent again;
a new episode remains independent. Disabling, pausing or rotating a channel keeps
its outstanding obligation, and prevents follow-up sends using a retired version.
A send already admitted before a configuration change may still finish; its
receipt is retained.

Telegram replies to the selected message ID and permits a missing parent to fall
back to a new message. Google Chat derives a stable thread key from the tenant,
channel, secret version, and subject, and asks Google Chat to fall back to a new
thread when necessary. Messages without a subject, including digests, are sent as
standalone messages without a reply option; Google Chat rejects a reply option
without a thread. Slack app delivery uses the bot adapter merged in PR #1570;
the reconciled adapter passes the shared subject anchor as `thread_ts` and retries
without that anchor when Slack reports that its parent no longer exists.

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
types and do not enforce the new send-time recipient policy. Workers predating
pending JSM request persistence also ignore stored request IDs and can repeat a
POST instead of resuming its status GET. Keep JSM disabled across the entire pool
until all workers support the new persistence contract. Drain pending JSM requests
before downgrading workers; preserve their request IDs and schema during rollback.

For pager lifecycle rollout, stop both producers and notification workers before
applying migrations `0267–0269`, then upgrade both before resuming. Producer code
assigns episodes, so a mixed deployment with old producers is unsupported. The
source and attempt guards reject old workers processing classified records.
Preserve episode tombstones, pending operations, pinned credentials and terminal
events during recovery; they cannot expire while old source events can replay.
The pager transport and gate migrations intentionally require forward recovery
instead of a Down migration that would erase unresolved external operations.

The JSM sandbox rehearsal on 2026-10-29 exercised a source-created finding,
worker restart with a persisted accepted request, two same-episode comments,
automatic close, reopen with a distinct alias, and a second automatic close.
All six operations reached provider-confirmed success. Native JSM inspection
showed both comments on the first alert and the reopened alert as a separate
record. The rehearsal used the existing Free integration without billing changes.
This covers the pager lifecycle path; it does not establish live PagerDuty
acceptance or complete the broader event/client matrix.

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

Main already includes migration `0228` for Slack bot channels and `0229` for
personal delivery, plus `0230` for ticketing. This branch's unshipped migrations use
`0231–0234` for subject threads, email settings, channel families and pending provider
requests, respectively. Apply the complete sequence in order; migrations on main remain
unchanged. Databases used for earlier branch rehearsals need an isolated rebuild
because their unpublished migration numbers differ from this sequence.

Use `SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED` to stop a provider globally and pause
an individual channel in tenant settings when investigating delivery. Clearing a
tenant relay returns delivery to the configured operator SMTP fallback. Remove an
approved email domain to revoke future domain-based recipients; validated domains
remain cached until explicitly removed. Rotate channel credentials by updating the
channel, which pins new deliveries to the resulting secret version.

## Acceptance evidence

The [historical channel ledger](https://github.com/KKloudTarus/synapse-ce/blob/4c851d90902a7db8925351d1f579b70064258fa3/docs/guide/notification-channels.md#acceptance-evidence)
records the original captures, provider retests, rollback rehearsals and limits. The
[provider retest receipt](assets/ui/notification-channels/live/provider-retest-receipt.json)
and [follow-up receipt](assets/ui/notification-channels/live/ready-review-receipt.json)
keep the tested revisions and fixture boundaries.

For later source operations, including the restored Gmail run, see the
[functional follow-up](notification-events-e2e.md#functional-follow-up).
The [delivery acceptance ledger](notification-delivery-acceptance.md) links
template, digest and personal delivery evidence. Track the remaining provider
setups in [#1576](https://github.com/KKloudTarus/synapse-ce/issues/1576).
