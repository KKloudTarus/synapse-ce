# Notifications and webhooks

[Documentation home](README.md)

Synapse can route tenant events to signed HTTP webhooks, Slack incoming webhooks,
Microsoft Teams, Telegram, Google Chat and Discord channels, and email recipients. Delivery runs in `synapse-worker`; API requests and scans do
not wait for a remote service.

## Personal email contacts

When notifications and SMTP are enabled, every authenticated human user can manage
their own email destinations at **My profile** (`/profile`). `GET` and `POST
/api/v1/me/contacts` list/add contacts; `POST
/api/v1/me/contacts/{id}/verification` queues a verification message; `POST
/api/v1/me/contacts/{id}/verify` consumes the eight-digit code; `DELETE
/api/v1/me/contacts/{id}` removes a manually managed contact. These endpoints
derive tenant and user from authentication. The admin user roster and user pickers
do not expose contact addresses or verification metadata.

Verification is a security message addressed only to the requesting user, outside
tenant notification rules and future personal mute preferences. It requires the
existing SMTP relay and a stable vault key on both API and worker. The API returns
`503` when SMTP is unavailable; it never claims that a contact was verified or an
email sent. The code expires in 10 minutes; only five attempts are allowed.
Resends are at least 60 seconds apart, with at most five requests per hour per
user. A replacement challenge, deletion, disable, or email change invalidates
pending delivery. The challenge code is encrypted at rest, and the durable job
contains only its challenge ID. A worker retry can produce a duplicate mail if
the SMTP relay accepted the first one before its acknowledgment was recorded.

A verified `email` and `email_verified: true` claim from the signed OIDC ID token
creates an identity-provider-managed contact for the account already resolved by
issuer and subject. Missing, false, null, and string `"true"` do not confer
verification. A later unverified claim revokes the prior provider-managed contact;
changed email increments its version. Email is never used to merge accounts.

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

### Disable a channel type deployment-wide

An operator can switch off any channel or provider type for every tenant, for
example while a vendor is compromised or a relay is being replaced:

```text
SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED=slack,email
```

Set the same value on `synapse-api` and `synapse-worker` and restart both. The
list is comma-separated, case-insensitive, and ignores blanks and repeats. Each
entry must name a type in the notification driver registry (`webhook`, `slack`,
`email` in this build); an unknown name stops startup, so a typo cannot leave
the type you meant to disable switched on.

While a type is disabled:

- `GET /api/v1/capabilities` leaves it out of `notifications.channel_types`, so
  **Settings → Alerting** no longer offers it for a new channel.
- Creating or testing a channel of that type answers `400` with a message naming
  the type and the variable. An existing channel of that type cannot be switched
  on or pointed at a new destination; it can still be renamed, switched off or
  deleted. The console marks it **Disabled by operator** and hides its test and
  enable actions.
- The worker cancels each queued delivery for it with `provider_disabled` before
  any connection is made. The cancellation is not a failure: it is not retried,
  does not dead-letter, and is never counted against the channel's own health,
  because the operator, not the channel, caused it.

Existing channels and their sealed configuration are kept. Removing the type
from the variable and restarting restores them; deliveries cancelled in the
meantime are not replayed. The switch covers tenant channels only; personal
inbox email and contact verification email use the SMTP relay directly.

## Configure routing

Open **Settings → Alerting**. Create a channel, test it, then create rules for one
of these events:

- `vulnerability_action.created`
- `scan.completed`
- `quality_gate.failed`
- `sla.approaching_deadline`
- `fleet.agent.offline`
- `incident.created`
- `finding.ownership_changed` (requires explicit `team_ids` or `all_teams` scope)

Each event type accepts only the rule filters its producer can satisfy, and a rule
with any other filter is rejected when it is saved:

| Event | Filters |
| --- | --- |
| `vulnerability_action.created` | severity floor, action types, engagements |
| `scan.completed` | engagements |
| `quality_gate.failed` | none |
| `sla.approaching_deadline` | engagements, lead time (24 hours by default) |
| `fleet.agent.offline` | none |
| `incident.created` | severity floor, engagements (when the incident has one) |
| `finding.ownership_changed` | engagements, teams (required) |
| `notification.destination_changed` | none; operator-driven, and a rule cannot target it |
| `notification.channel_paused` | none; sent in-app to tenant administrators when a channel pauses, and a rule cannot target it |

The severity floor is inclusive. Quality gate and fleet events carry no engagement,
so an engagement scope on them could never match. Rules of that shape saved before
this check were disabled on upgrade with `disabled_reason: engagement_filter_unsupported`;
their engagement list is kept so you can see what was intended. Remove the engagement
scope and save the rule to enable it again.

`GET /api/v1/notifications/event-types` returns this catalog to any signed-in member:
each type's label, accepted filters, maximum data class, template variables and whether
it is mandatory or operator-only. The rule form in **Settings → Alerting** is built from
it, so it offers only rule-eligible types and shows only the filters the selected type
accepts.

An incident carries the engagement its fleet correlation was scoped to. Incidents recorded
before correlation was scoped to an engagement may carry none, and an engagement-scoped
incident rule does not see them. Leave the scope empty to receive every incident.

Engagement and team scope use searchable pickers over the existing engagement
list and ownership team pages. Each choice keeps its stable ID beside the
display name, including when two records share a name. A saved ID that the
directory no longer returns stays on the rule, with a warning, until an
administrator removes it. Removing it is the only way the rule becomes broader.
Archived teams can remain selected and are marked archived. Personal recipient
roles are not offered here: the event catalog that decides which roles an event
supports is still open (#1339), and a rule must not grow a recipient filter
ahead of that contract.

The engagement list endpoint returns the tenant's engagements in one response,
and the picker requests that list once, then shows 25 matches at a time. Team
search walks the existing cursor pages and does not download a user directory.
The picker does not include email addresses or contact verification state.

## Language and time zone

**Settings → Language & time zone** sets the language (`en` or `vi`) and the IANA
time zone that this tenant's messages and digests use. A tenant that never saves
them uses English and `UTC`. The zone is stored as a name such as
`Asia/Ho_Chi_Minh`, not an offset, so daylight saving is applied at render time.
`Local` and offsets such as `+07:00` are refused.

Any role can read the settings through `GET /api/v1/tenant/settings`. Only
tenant administrators can change them with `PUT /api/v1/tenant/settings`, which
takes the `revision` the caller read and answers `409` when another
administrator saved first. Each change is written to the audit log.

## Custom message templates

A tenant can replace the wording of a message with its own template. Templates
are managed in the console under **Settings → Templates** (`/settings/templates`,
also linked from the Messaging group of **Settings → Integrations**) or over the
API. The console lists custom templates by event type and channel family, and its
editor offers a variable picker (each variable's description, data class and list
cap), shows an engine rejection under the field it names with its line, and
saves, activates, rolls back and archives versions. Built-in defaults will be
listed there, read-only with "clone to customize", once the default template set
ships. Every route needs `manage_integrations` (`admin` or `integration_admin`), takes the
tenant from the session, and is registered only when notifications are enabled.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/notifications/templates` | List templates; filter by `event_type`, `family`, `locale`, `status`; page with `after` and `limit` |
| `POST /api/v1/notifications/templates` | Create a draft with version 1 |
| `GET /api/v1/notifications/templates/{id}` | The template, its newest version (`latest`) and the version that renders (`active`) |
| `PATCH /api/v1/notifications/templates/{id}` | Save a new version (and optionally rename); what renders does not change |
| `GET /api/v1/notifications/templates/{id}/versions` | Versions, newest first; page with `before` and `limit` |
| `POST /api/v1/notifications/templates/{id}/activate` | Make a version render (`version` omitted or `0` means the newest) |
| `POST /api/v1/notifications/templates/{id}/rollback` | Activate an earlier `version` |
| `POST /api/v1/notifications/templates/{id}/archive` | Retire the template |
| `POST /api/v1/notifications/templates/preview` | Prepare a preview for a channel and event type without sending (see below) |
| `GET /api/v1/notifications/templates/preview/events` | The tenant's 20 newest events of an `event_type` a preview can use; also needs `view` |

A template is keyed by event type (a catalog type or `*`), channel family and
locale (`en`, `vi` or `*`); the key never changes. Each family has fixed
content fields: `chat` has `title` and `body`, `email` has `subject` and
`body`, `pager` has `summary`, `ticket` has `summary` and `description`, and
`webhook` has `body`. At most one template per key is active: activating one
archives the key's previous active template in the same transaction and returns
its ID as `archived_template_id`. Versions are append-only, so a rollback
activates an earlier version instead of rewriting one. Every mutation takes the
`revision` the caller read and answers `409` when it is stale.

Every non-empty field is compiled when it is saved, and again when a version is
activated, by the template engine against the variables the event type declares
in the event catalog (`GET /api/v1/notifications/event-types`). A `*` template
is compiled against every catalog event type, so it can only use variables all
of them declare. A rejected field answers `400` with the field, the event type,
the engine code (for example `unknown_variable`, `forbidden_function`,
`parse_error` or `iteration_bound_exceeded`) and the line. The message ends with
the engine's short detail, such as the unknown name or the parser's message, capped
at 200 characters; the response never repeats the template source:

```json
{"error": "template field \"body\" is invalid for event type incident.created: unknown_variable at line 2: nope",
 "field": "body", "event_type": "incident.created", "code": "unknown_variable", "line": 2}
```

Every event type declares its template variables in the catalog. Five are
common to all of them, so a `*` template can use these: `event_type`,
`event_label` and `occurred_at` (signal class), and `title` and `summary`
(summary class). The others are per type:

| Event type | Signal | Summary | Detail |
|---|---|---|---|
| `vulnerability_action.created` | `severity`, `action_type` | `engagement_name` | |
| `scan.completed` | `scan_kind` | `engagement_name`, `target` | |
| `quality_gate.failed` | `failed_conditions` | `project_name` | |
| `sla.approaching_deadline` | `tier`, `deadline`, `lead_time_hours` | `engagement_name`, `finding_title` | |
| `fleet.agent.offline` | `last_seen_at` | `agent_name` | |
| `incident.created` | `severity` | `engagement_name` | `asset_name` |
| `finding.ownership_changed` | | `engagement_name`, `finding_title`, `old_team`, `new_team`, `old_assignee`, `new_assignee`, `actor`, `reason` | |

When an event is recorded, its builder takes a snapshot of these values and
stores it with the event. The snapshot keeps only declared variables up to the
event type's maximum data class, with invisible and direction-changing
characters removed, line breaks turned into spaces, and each value capped at
1,000 characters. Times are RFC 3339 in UTC. The snapshot is not part of the
webhook body, which stays the raw event. Names (engagement, project, finding,
team, assignee, agent, asset) are read from the source records when the event
is recorded, so a later rename does not change a message already queued.
`target` is the scan target without its credentials, query or fragment.
A template reads a variable that has no value, for example the asset of an
incident without one, as an empty string.

Captured sources (scan jobs, quality gates, incidents) are recorded by a
database trigger. The worker can also compose an event's data from the source
rows when a captured record carries only its identity, producing the same object
the webhook body has always carried; the trigger keeps writing the data until
every running worker can compose it. No event declares a list variable yet, so a template
cannot `range` over one. The `webhook` family's `body` is compiled as text; the
structured JSON body of a custom webhook is validated separately when that
feature lands. Channels carry no data class and cannot be bound to a template
yet, so saving does not yet warn about bound channels whose class is below a
variable the template uses.

### Template preview

`POST /api/v1/notifications/templates/preview` takes a `channel_id` and a
catalog `event_type` and prepares a preview without sending or storing
anything:

- **Sample event.** By default the event type's published fixture
  ([event schemas](schemas/events/README.md)), with its illustrative engagement
  dropped. With `event_id`, one of the tenant's stored events of that type, as
  listed by `GET /api/v1/notifications/templates/preview/events?event_type=`
  (newest first, at most 20). A stored event also needs `view`, because it
  describes engagement data; another tenant's event is not found.
- **Template text.** By default what resolution would pick for the channel
  (the `resolution` field, as for the rule form). With `template_id`, a saved
  version of that template (`version`, or the latest); the template must be of
  the channel's family and cover the event type. With `fields`, unsaved text:
  alone for a new template, with `template_id` for an unsaved edit. Unsaved
  text goes through the same engine checks as a save and answers the same `400`.

The response names the channel, the sample and the template; it never carries
the event's data, its template context or template source, and it is never
logged. Rendering uses the send-time renderer, so preview and delivery cannot
differ: until that renderer lands (#1365) the response has `"rendered": false`
and no message. It will then carry the message at the channel's data class, and
the suppressed state when the engagement's override is `none`.

Every create, update, activation, rollback and archive is written to the audit
log (`notification.template.created`, `.updated`, `.activated`, `.rolled_back`,
`.archived`) with the actor, the key, the status, the versions involved, the new
version's checksum, and a diff summary. The summary lists each changed field as
`field:+added/-removed`, counting lines added and removed (for example
`body:+2/-1,title:+1/-0`), or `none`. It never quotes template source.

## Personal inbox

When notifications are enabled, each human user has an inbox at `/inbox` and a bell in the application header. `GET /api/v1/me/inbox` and `GET /api/v1/me/inbox/unread` are scoped to the signed-in user. Machine roles are denied. The bell polls at most every 30 seconds and pauses while the tab is hidden. A deployment without the inbox returns 404 and the bell stops asking.

Inbox rows are written in the same database transaction as the notification event. In-app delivery does not create a channel delivery or a job. Replaying an event after retention does not recreate a deleted row. Mark-all-read uses the server time of that request, so a message that arrives while the request is running stays unread.

Personal recipients come from structured IDs already on the event: the canonical finding assignee and active ownership team members. A legacy assignee label, an email address, or a display name is never resolved into a recipient. Mentioned users, approvers, and engagement leads stay unsupported until a producer records a verified identity. `notification.destination_changed` is mandatory in-app for enabled tenant admins. It is not a routing rule and cannot be muted. One notice is stored per channel revision: repeating that save is a no-op, and changing only the secret or the URL path is not a host change. Changing back to an earlier host writes a new notice. The payload contains the actor, the action, the channel class, and the scheme plus host. It does not contain a URL path, query, port secret, or credential. `notification.channel_paused` is mandatory in-app for enabled tenant admins in the same way, once per automatic pause (see [Channel health and automatic pause](#channel-health-and-automatic-pause)).

`PUT /api/v1/me/notification-preferences` stores `inherit`, `enabled`, or `disabled` for the signed-in user. Mandatory in-app wins over an explicit mute, and an explicit mute wins over the default for every other choice. Personal email is sent only to the verified contact version captured when the event was projected. A later email change does not retarget a message that is still queued. Personal delivery is currently available for finding ownership changes, approaching SLAs, and destination-change notices. Other framework event types, Slack direct messages, and Teams personal delivery are shown as unavailable until they have a structured personal recipient and subject.

Events created before the framework first
activates for a tenant are not replayed automatically.

### Who can manage notifications

Two roles hold the `manage_integrations` permission: `admin` and `integration_admin`.
It lets a user read, test, rename, enable, disable, resume and delete channels, create
and edit routing rules, manage message templates, and read delivery history and
quarantined sources. Actions that point Synapse at a new destination still require
`administer`, which only `admin` holds:

| Action | `integration_admin` | `admin` |
| --- | --- | --- |
| List, read, test, rename, enable, disable, resume or delete a channel | yes | yes |
| Create, edit or delete a routing rule; read delivery history | yes | yes |
| Create a channel | no (`403`) | yes |
| Change a channel's URL, secret or email recipients | no (`403`) | yes |

A `PATCH` that sends the channel's current recipients back is not a change. Machine
roles (`agent`, `mcp`) never hold either permission. Every channel audit entry records
the actor and the destination masked to `scheme://host` (`mailto://` and the recipient
domains for email); an update also records `destination_changed` and, when it is
`true`, the previous masked destination. Channels carry no data class yet, so none is
recorded.

Channel type is immutable. Editing a URL or
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

If a captured source fails event validation, the worker quarantines that source
and continues with the next one in the same poll. Delivery history shows its
event type, source identity and a fixed reason code; captured payloads are never
returned. An oversized event reports `event_data_too_large`; other validation
failures report `invalid_event`. Quarantined sources are not retried automatically.

SLA and fleet relevance is checked again immediately before sending. Resolving an
SLA, changing its assessment/deadline, entering an exception, passing the deadline,
or receiving a new heartbeat cancels the old pending reminder.

Channel tests return `202` with a delivery ID. This means the test is durably
queued; inspect Delivery history for the final result. Disabling or deleting a
channel cancels pending deliveries, and so does an automatic pause (see
[Channel health and automatic pause](#channel-health-and-automatic-pause)).
Existing in-flight requests cannot be recalled.

## Webhook contract

The [versioned event schemas and fixtures](schemas/events/README.md) cover every catalog event type, including operator-only channel tests and destination notices. Each schema validates the complete event envelope and event-specific `data` object. Optional additive fields retain v1; removing or renaming a field requires a new version.

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

## Chat channels: Teams, Telegram, Google Chat and Discord

Four more chat channel types deliver the same events (#1378 to #1381). For each of them the
URL, or the Telegram bot token, is the credential: it is sealed like a webhook secret, the API
and the console show only `https://host/…`, and editing a channel never shows it again. To point a
channel somewhere else, an administrator enters the whole URL (or, for Telegram, the token and chat)
again; a rename or an enable switch keeps it. Validation pins each type to its vendor's hosts, and
`safehttp` still vets every address at dial time, so a chat channel cannot reach an internal host.
A failed request is recorded only as a code (`network_error`, `destination_blocked`, `http_<status>`),
never with the request URL.

| Type | What to paste | Accepted destination |
|---|---|---|
| `teams` | The URL of a Teams **Workflows** "post to a channel when a webhook request is received" flow | `https://*.logic.azure.com/workflows/…`, `https://*.logic.azure.us/workflows/…` or `https://*.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/…`, with its `sig` parameter. Office 365 connector URLs (`*.webhook.office.com`) are retired by Microsoft and refused. |
| `telegram` | A bot token from @BotFather, the chat ID, and optionally a forum topic ID | Bot API `sendMessage` on `api.telegram.org`. The chat is a numeric ID (groups and channels start with `-100`) or an `@channel` username; the bot must be a member of the chat. |
| `google_chat` | The space's incoming-webhook URL | `https://chat.googleapis.com/v1/spaces/<space>/messages?key=…&token=…`, with no other parameters. |
| `discord` | A channel webhook URL | `https://discord.com/api/webhooks/<id>/<token>` (also `discordapp.com`, `ptb.` and `canary.`), optionally with `thread_id`. |

Each message has the event title, the event summary and the event type and ID, rendered by the
channel's formatter so that no value can become formatting, a link or a mention:

- **Teams** posts an Adaptive Card whose text is all `TextRun`s, which Teams shows literally. The
  Workflows trigger answers `202 Accepted` and returns no message handle.
- **Telegram** sends MarkdownV2 text with every special character escaped and link previews off. A
  `429` carries its wait in the body (`parameters.retry_after`), which the worker honours. A group that
  was upgraded to a supergroup fails with `telegram_chat_migrated`; re-enter the channel with the new
  chat ID. The sent `message_id` is kept on the delivery for threading (#1384).
- **Google Chat** posts a `cardsV2` card whose text is HTML with every value escaped, so
  `<users/all>` is text. The created message's resource name is kept on the delivery.
- **Discord** posts one embed with every punctuation character of a value escaped and
  `allowed_mentions.parse` always empty, so `@everyone` and role mentions never ping. The driver adds
  `wait=true` so Discord returns the created message, whose ID is kept on the delivery.

Until the send-time renderer (#1365, #1367) lands, these channels use the same built-in title and
summary as Slack, and a bound chat template does not change their content yet. The formatters are the
ones the template preview uses, so the switch will not change how a message is escaped. Deep links
arrive with the renderer.

All four are `2xx` delivered, `408`, `429` and `5xx` retried with the usual budget, and any other
status final. Each type can be switched off deployment-wide with
`SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED` (for example `telegram,discord`).

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

The **worker** exports delivery health on its own, isolated `/metrics` listener when
`SYNAPSE_NOTIFICATIONS_ENABLED=true` and `SYNAPSE_METRICS_ENABLED=true`.
Use `SYNAPSE_METRICS_ADDR=127.0.0.1:9091` for a worker running beside the API;
the default `9090` port is already used by the API on the same host. The listener
is **unauthenticated**: allow only a loopback or private scrape network.
For `inClusterBroker` Helm installations, set `worker.metrics.enabled=true`,
enable notifications via `extraEnv`, and scrape the worker-only ClusterIP
Service from `worker.metrics.monitoringNamespace`. The chart creates a
matching ingress NetworkPolicy; the default remains disabled. The
`integrations` and `lifecycle` worker profiles do not process channel deliveries
and do not serve these metrics. The API never duplicates worker delivery counters.

Worker metric names all start with `synapse_notification_worker_`:
- `sent_total` and `failed_total` count **committed delivery attempts**. Failed
  includes attempts scheduled to retry, not just final delivery failures.
- `dead_lettered_total` counts committed terminal transitions observed by the
  worker, separately from the unsuccessful attempt that caused them.
- `delivery_duration_seconds` is a histogram of attempt processing time; it
  deliberately excludes the time a delivery waits in the durable queue.
- `oldest_pending_age_seconds` shows the oldest pending/retrying delivery age
  across all tenants, computed from tenant-scoped PostgreSQL reads on each scrape.
  An empty family reports 0. On any database read error all age gauges are
  omitted and `pending_scrape_error` reports 1 (0 on a healthy scrape).
- `template_fallback_total` counts committed attempts whose email/Slack
  rendering had to use built-in title or summary fallback content. Generic
  webhooks send the event JSON and do not render that content.

Every per-channel metric has only `channel_type` and `provider` labels.
The fixed combinations are `webhook/generic`, `slack/slack`,
`email/smtp`, and `other/other` for unknown types. No tenant ID,
channel ID, recipient, host, URL, provider credentials or raw error text
can become a metric label. Counters restart with each worker process;
the pending-age gauge reads durable state at scrape time.

Administrators can manually redrive one dead-lettered channel delivery from
**Settings → Alerting → Delivery history**, or call
`POST /api/v1/notifications/deliveries/{id}/redrive` with a 1–500 character
`reason` and `expected_fence` set to the delivery's current `redrive_fence`. The API requires administer
permission. Redrive reuses the same event, delivery and queue job, resets the
queue's eight-attempt budget, and preserves the lifetime attempt count and all
attempt records. Its reason and safe destination summary are audited. A stale
fence, non-dead delivery, missing queue job, or changed channel configuration
returns a conflict.

Audit reasons remove URLs and known channel credentials, including common encoded
forms. If the API cannot open the delivery's bound channel configuration to scrub
those credentials, it returns a conflict before queuing work. Email audit and
confirmation destinations name only the original recipient's domain.

Redrive is allowed only while the original channel remains enabled, present,
unpaused and enabled for its channel type. Webhook and Slack deliveries keep
their sealed channel version; an email delivery is eligible only while its
original recipient remains configured. Redrive never retargets an event or
recipient and does not resume a channel. A channel rename or resume does not by
itself invalidate the original destination binding. Retry is still at least
once: if a receiver accepted the earlier request before its acknowledgement was
lost, redrive can send a duplicate. The confirmation asks for an operator reason
and states this risk.

The redrive transition clears only the delivery's current template pin and
keeps attempt-level references. Fresh active-template resolution is part of
#1365; clearing the pin here alone does not implement that renderer or prove a
redrive uses a newer template. Until #1365 lands, this reset does not change the
rendered content.

### Rolling out redrive

Deploy the cycle-aware `synapse-worker` release to every worker before deploying
the API release that exposes redrive. Wait until all older workers have stopped
and their in-flight jobs have drained before administrators use the action. The
new worker records the queue claim fence when it dead-letters a delivery, and
reconciliation uses that fence to avoid applying an old failure to a later
redrive cycle. An older worker callback has no cycle fence and can otherwise
mark a redriven delivery dead-lettered again. If rolling back, first stop
redrives and drain all redriven jobs and callbacks, or restore a worker release
that understands the cycle fence; do not run an older worker against active
redrive cycles.

## Channel health and automatic pause

The worker keeps a failure count on every channel so that a broken destination is
not retried forever. After `SYNAPSE_NOTIFICATION_CHANNEL_PAUSE_THRESHOLD`
(default `5`) consecutive **permanent** failures the channel is paused and every
enabled tenant administrator gets one in-app notice.

What counts:

| Attempt result | Effect on the count |
| --- | --- |
| Delivered | Resets it to zero |
| Final failure the channel owns: `destination_blocked`, `smtp_destination_blocked`, `channel_config_invalid`, `smtp_recipient_invalid`, HTTP 4xx other than 408 and 429 (`http_4xx`), SMTP 5xx (`smtp_5xx`) other than the RFC 4954 AUTH replies 530, 534, 535 and 538, which describe the shared relay credential | Adds one |
| Retryable failure: network errors, HTTP 408, 429 and 5xx, SMTP 4xx, including the eighth one that exhausts a delivery | None: it neither adds nor resets |
| Final failure the operator owns: `smtp_not_configured`, `smtp_sender_invalid`, `smtp_tls_required`, `smtp_auth_unavailable`, `channel_secret_unavailable`, and internal codes such as `encode_failed` | None |

Failures only count while the channel is active. The attempt result, the count and
a pause commit in one transaction, so a crash cannot record a failure without
counting it or pause twice. `0` disables pausing but the count is still kept and shown.

When a channel pauses:

- Pending and retrying deliveries that have not started are **cancelled** with
  `last_error: channel_paused`, the same way disabling a channel cancels them.
  They are not held for later: a backlog of stale alerts released on resume would be
  worse than none. An attempt already in flight finishes; its result no longer
  changes the paused state (a late success does not resume the channel).
- New events do not create deliveries for the channel, and a channel test returns
  `409 Conflict`.
- A `paused` row is appended to the channel's health history with the delivery and
  attempt that tripped it, and the worker writes a `notification.channel.paused`
  audit entry with actor `system`.
- Enabled tenant administrators get a mandatory in-app notice
  ([`notification.channel_paused`](schemas/events/README.md)), once per pause. It
  names the channel, its type, the failure count and the last failure code. It never
  contains the destination URL, a recipient, a response body or error text. Users can
  opt in to an email copy in their inbox preferences. The notice is not a routing
  event: a rule cannot target it and it is never sent to a channel.

Resume a channel from **Settings > Alerting** (the **Resume** button next to the
**Paused** badge) or with `POST /api/v1/notifications/channels/{id}/resume` and the
body `{"revision": <current revision>}`. Resuming needs `manage_integrations`, so an
`admin` or an `integration_admin` can resume. A
resume clears the pause and the count, bumps the channel revision, appends a
`resumed` row naming the user and writes a `notification.channel.resumed`
audit entry. Deliveries cancelled during the pause are not re-sent. Fix the
destination first: if it still fails, the channel pauses again after another
run of permanent failures, and administrators get a new notice.

A pause is health, not configuration, so it does not change the channel revision:
an edit an administrator started before the pause still saves, and it does not
clear the pause. Replacing the URL or secret resets the count of an active channel.

`GET /api/v1/notifications/channels/{id}` returns `health` with `state`
(`active` or `paused`), `paused_at`, `paused_reason`
(`consecutive_permanent_failures`), `consecutive_failures`, `last_failure_code`
and `last_failure_at`. `GET /api/v1/notifications/channels/{id}/health-events`
returns the append-only pause and resume history, newest first. The Integrations
hub shows a paused channel as **Paused** on its Messaging card.

### Legacy incident webhook (deprecated)

`SYNAPSE_ALERT_WEBHOOK_URL` is deprecated and will be removed in **0.4.0**. It is a
single deployment-wide, best-effort webhook that the API calls in-process when
correlation opens an incident. Tenant `incident.created` rules replace it: they are
durable, retried, per tenant, and recorded in delivery history.

`incident.created` rules now deliver whether or not the legacy URL is set. Before
this release the worker suppressed the `incident.created` producer while the legacy
URL was configured, so those rules were accepted but never fired. While both are
configured, every incident is sent twice: once to the legacy URL and once to each
channel a matching rule selects. Each path delivers an incident at most once to its
own destinations, but the two paths are not deduplicated against each other. If a
rule points at the same receiver as the legacy URL, that receiver gets two requests.

Startup logs a warning on the API and the worker while the legacy URL is set. The
URL itself is never logged. **Settings → Alerting** shows a warning on the rule
form for `incident.created` while the legacy webhook is set, and you must
acknowledge it before you can save the rule. The console only learns whether the
legacy webhook is set, through the `legacy_alert_webhook` entry of
`GET /api/v1/capabilities`. It never sees the URL.

To migrate:

1. Create a channel for the receiver and test it.
2. Create an `incident.created` rule with the same severity floor as
   `SYNAPSE_ALERT_MIN_SEVERITY`, and acknowledge the warning.
3. Remove `SYNAPSE_ALERT_WEBHOOK_*` from the API and restart it. The worker no
   longer reads the URL. Incidents recorded while the worker previously suppressed
   `incident.created` are not replayed.

Initial activation is persisted per tenant. Disabling the framework pauses delivery
but keeps retained records and the activation cutoff.

### Secret rotation and retention

Use channel editing to rotate destinations and signing keys. Keep the previous
receiver key valid until its pending deliveries have completed. Channel deletion is
soft deletion; immutable event, attempt and encrypted version history remains.
This release has no automatic retention purge. Monitor database size and retain
the vault master key with database backups. Replacing the master key directly
makes existing ciphertext unreadable; master-key rotation requires an
operator-controlled offline decrypt/re-encrypt migration of every retained
channel version using the same tenant/channel/version associated data.
