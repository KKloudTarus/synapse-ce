# Governed document publishing

[Documentation home](README.md) · [Configuration](configuration.md) · [Notification channels](notification-channels.md)

Synapse can publish a bounded, deterministic stored-source report to an existing
Confluence Cloud or Data Center integration. It supports `engagement_report`,
`assessment_closure_report`, and `project_quality_summary`. The API admits a
durable command; a worker performs the remote write. The release actor, tenant,
scope, current authority, source release policy, legal hold, destination revisions,
evidence-chain integrity, and secret redaction are checked again before each
sensitive remote step.

This requires PostgreSQL. The API enables publication only with the PostgreSQL
document store. A `synapse-worker` with either the `all` or `integrations` profile
advances scheduled report delivery and builds report artifacts. The `integrations`
profile uses fail-closed dispatch-only scan ports while it reads verified stored
report data; it does not claim scan, recon, or assessment-lifecycle jobs.

In the console, open **Settings → Integrations → Documentation**, then choose
**Manage documentation**. The configuration editor is headed **External
integrations** and lists the available Confluence Cloud and Data Center providers.
The Documentation group is available when the API has the same durable PostgreSQL
store that wires document publishing; it is not a separate feature switch.

## Configure Confluence

Create an enabled `confluence-cloud` or `confluence-dc` integration with a
`detail` data class, one Confluence space key, and one exact read group. Cloud
uses an Atlassian account email and API token. Data Center uses a personal access
token and also needs the deployment's explicit self-hosted integration host
allowlist. Do not put credentials in the endpoint or configuration fields.

The group identifier has provider-specific meaning:

| Provider | `read_group` value |
| --- | --- |
| Confluence Cloud | Exact Atlassian group **ID** |
| Confluence Data Center | Exact Confluence group **name** |

For Cloud, set `org_id`, `site_ari`, `policy_id`, and `org_api_key` together when
the organization can supply a current public-link policy read. Before sensitive
content can be uploaded, Synapse verifies the exact page ACL and proves that the
configured site has a blocking public-link policy. The organization policy API may
be unavailable, changed, deprecated, or unavailable on a Free plan. Any missing,
incomplete, stale, or unreadable proof blocks the release; a successful connection
test is not proof that sensitive publication can proceed.

Cloud restriction creation uses the V2 direct-permissions replacement and
`VIEW_RESTRICTED` state APIs. The integration actor must retain effective access
through the configured group. Synapse leaves the provider's self-lockout protection
enabled. Before upload, both V2 state/complete direct grants and V1 read/update
ACLs must agree with the configured group, followed by the current public-link
policy proof. A tenant without the required V2 API fails closed.

For Confluence Data Center 10.2 LTS, setting the optional boolean
`legacy_xmlrpc_restrictions` to `true` selects the vendor-documented compatibility
path for group-only restriction creation. It reuses the PAT; no password or RPC
session credential is needed. An administrator must enable authenticated Remote
API access in Confluence's Further Configuration first and leave anonymous access
disabled. Synapse never enables it automatically. Other provider versions, missing
group membership, unavailable RPC, or unverifiable results fail closed.

XML-RPC is deprecated and planned for removal in Confluence 11. Keep this option
off unless the tested compatibility path is needed. It is not a fallback after a
REST error. View/Edit writes still require exact group-only REST readback before
any report upload. See the
[vendor workaround](https://jira.atlassian.com/browse/CONFSERVER-56405) and
[restriction design](../evidence/jira-sync-report-publishing/restricted-publication-design.md).

The first remote write is only a neutral recovery shell. Synapse applies the exact
read ACL and verifies it, including the Cloud public-link proof, before it uploads
a PDF or image attachment or writes the actual title and body. An ACL alone does
not satisfy the Cloud public-link check.

## Release and unpublish

Use `POST /api/v1/document-publications` with an existing integration, source
kind, source reference, scoped ID, and a unique request key. An engagement report
uses engagement scope; assessment closure and project quality reports use project
scope. Source references are stable identifiers such as `engagement:<id>`,
`assessment-cycle:<id>`, or `project:<id>`; a report revision belongs in the
stored artifact, not the reference.

The same `(tenant, integration, request_key)` returns the existing command only
when its full payload is identical. A changed payload is a conflict. Inspect
`GET /api/v1/document-publications/{id}` and the link lists under an engagement or
project instead of assuming that `202 Accepted` means the remote write completed.

`DELETE /api/v1/document-links/{id}` accepts a separate request key and creates a
governed purge command. Confluence deletes every attachment, including its trash
or permanent-purge phase, before deleting the page with the same whole-object
procedure. A retired link cannot be recreated for that target.

A timeout, crash, expired lease, partial purge, or ambiguous provider response is
`uncertain`. Synapse does not retry an uncertain operation blindly. It reconciles
the durable marker and requires a unique verified remote result before it can
finish. Keep the intent and audit history while resolving an uncertain state.

## Scheduled delivery

Schedules are available only when PostgreSQL, notifications, a shared vault key,
the API, and an `all` or `integrations` worker are configured. They run weekly or monthly in an IANA
time zone. Weekly `weekday` uses Sunday `0` through Saturday `6`; monthly `day`
uses `1` through `31` and clamps to the last day of shorter months. A nonexistent
DST wall minute advances to the first real minute; an ambiguous wall minute uses
the first occurrence. The selected UTC due instant is stored durably.

Each due occurrence builds and freezes one stored artifact before delivery. A
Confluence schedule uses that frozen artifact for its command. An email schedule
uses the same PDF as an attachment. The occurrence, content hash, remote page
state, and per-recipient delivery counters are available from
`GET /api/v1/document-schedules/{id}/runs`.

Email schedules select an existing enabled `detail` email notification channel
whose recipients are currently verified. They do not accept raw recipient
addresses, relay settings, or SMTP credentials in the schedule request. Recipient
verification and relay configuration are checked again immediately before SMTP
DATA. An SMTP result that is ambiguous after DATA is recorded as uncertain and is
never resent automatically; resolve it from the safe run history and mail system
evidence.

Saving, disabling, and executing a schedule rechecks current document-release
authority, source policy, legal hold, destination configuration, and current
recipient/channel eligibility. A stale expected version conflicts rather than
overwriting a schedule.

## Operational evidence

Apply the new migrations with the migration-owner credential before starting
updated APIs and workers. Upgrade all writers before enabling automatic ticket
submission, grouped updates, or report schedules. Before rolling binaries back,
disable the affected integrations and schedules and let in-flight work settle.
Keep the durable command and delivery tables: rollback guards deliberately refuse
to remove populated history. Use a forward migration to repair persisted data.
The upgrade requires a maintenance window: drain all database clients before
migration. Backfill and constraint work can block reads as well as writes. Rehearse
against a restored representative database and follow the
[migration rollout procedure](deployment.md#migration-rollout).

Run a narrow canary in an isolated restricted space and group first. Retain the
intent, audit record, stored content hash, and provider response classification.
For Cloud, retain proof that the exact group ID, site ARI, and public-link policy
were verified immediately before sensitive content was written. For Data Center,
retain the matching exact group name and space proof. Never record API tokens,
organization keys, SMTP credentials, recipient addresses, report body, or PDF
bytes in operational evidence.
