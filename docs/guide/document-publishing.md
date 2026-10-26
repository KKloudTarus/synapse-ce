# Governed document publishing

[Documentation home](README.md) · [Configuration](configuration.md) · [Notification channels](notification-channels.md)

Synapse can publish a bounded, deterministic stored-source report to an existing
Confluence Cloud or Data Center integration, a restricted Google Drive folder, a
restricted SharePoint or OneDrive Business folder, or a restricted prefix of an
S3-compatible bucket. It supports
`engagement_report`, `assessment_closure_report`, and `project_quality_summary`.
The API admits a durable command; a worker performs the remote write. The release
actor, tenant, scope, current authority, source release policy, legal hold,
destination revisions, evidence-chain integrity, and secret redaction are checked
again before each sensitive remote step.

This requires PostgreSQL. The API enables publication only with the PostgreSQL
document store. A `synapse-worker` with either the `all` or `integrations` profile
advances scheduled report delivery and builds report artifacts. The `integrations`
profile uses fail-closed dispatch-only scan ports while it reads verified stored
report data; it does not claim scan, recon, or assessment-lifecycle jobs.

In the console, open **Settings → Integrations → Documentation**, then choose
**Manage documentation**. The configuration editor is headed **External
integrations** and lists the registered providers and their supported capabilities. The
Documentation group is available when the API has the same durable PostgreSQL store
that wires document publishing; it is not a separate feature switch.

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
policy proof. A tenant without the required V2 API fails closed. The known control
names follow the [Atlassian data-security cookbook](https://developer.atlassian.com/cloud/admin/cookbook-dsp/).
Recognized control effects and observed vendor audit fields are explicitly typed;
unknown fields, conditions, duplicate keys or malformed values cannot prove an
unconditional public-link block.

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

## Configure Google Drive

Create an enabled `google-drive` integration with endpoint
`https://www.googleapis.com`. Set `space` to the ID of a dedicated restricted
parent folder in the integration actor's **My Drive**, `read_group` to the exact
Google Drive group permission ID, and `data_class` to `detail`. Store the scoped
Drive OAuth access token only in the write-only `access_token` credential field.
This profile accepts an access token, not a refresh token, service-account key or
OAuth client secret. Synapse does not refresh it. Its lifetime is set by Google
and the grant; record the expiry in your credential operations and replace the
sealed value before it expires. Scheduled releases and restriction checks use the
current credential and fail closed when it expires. A successful connection test
does not establish that the token will still work at a later schedule.

The destination must remain a service-owned My Drive folder. Before a neutral
shell, each attachment upload, and the body write, Synapse proves the configured
folder has exactly its authenticated owner and the configured group as reader. It
also proves the same restricted ownership and reader permission for the generated
publication folder and every managed child. Shared Drives, extra principals,
public links, incomplete permission listings, changed ownership, and unverifiable
permissions block the release. `space` is the immutable destination container;
do not repoint it to a different folder after a link has been published.

## Configure SharePoint or OneDrive Business

Create an enabled `sharepoint` or `onedrive` integration. Its endpoint is the
authoritative HTTPS SharePoint site origin, including the configured site path
when applicable, for example `https://tenant.sharepoint.com/sites/security`.
It must not contain credentials, a query, or a fragment. Configure the following
fields:

| Field | Required value |
| --- | --- |
| `drive_id` | The Microsoft Graph drive ID for the destination. |
| `space` | The restricted folder item ID in that drive. |
| `folder_path` | The matching server-relative restricted folder path, such as `/sites/security/restricted`. |
| `read_group` | The exact Microsoft group principal ID. |
| `custodian_principal_id` | The service custodian's SharePoint principal ID. |
| `data_class` | `detail`. |

Supply a scoped Microsoft Graph access token in `access_token` and a separate
scoped SharePoint REST access token in `sharepoint_token`. Both credentials are
sealed and write-only. The `sharepoint` profile accepts a `documentLibrary` drive;
the `onedrive` profile accepts a Business drive. Personal OneDrive is outside this
profile.

Both Microsoft fields accept access tokens for their respective audiences, not
refresh tokens or client secrets. Synapse does not refresh either token. Track
both provider-issued expiry times and rotate the sealed fields before expiry;
a live Graph token cannot replace an expired SharePoint REST token. Scheduled
publishing and restriction checks fail closed if either proof becomes unavailable.
Plan credential renewal with the identity owner before enabling schedules.

For both Drive and Microsoft, rotation advances the connection's credential
revision. An already approved command is pinned to its original revision and
refuses to write after rotation; do not edit its stored checkpoint to resume it.
Review any pending or uncertain command through the governed recovery workflow
before approving a release with the new credential. Restriction monitoring reads
the current credential independently of the original publication approval.

Before release, Synapse binds the Graph drive and configured folder to the
authoritative SharePoint site and folder path. It requires unique SharePoint role
assignments containing exactly the configured group with the reader role and the
configured custodian with full control. Public Graph links, inherited container
permissions, additional principals, custom roles, incomplete role listings, or a
mismatch between Graph and SharePoint identities fail closed. The neutral shell,
its body, and managed attachments are checked again before sensitive writes.

The publication folder retains a conditional-write ownership manifest binding each
managed attachment name to its exact Graph item ID. This permits staged republish
attachments while refusing manual files or a changed ownership manifest. Interrupted
neutral-shell creation is recovered by its exact marker; missing neutral files are
completed only after fresh restriction proof.

## Configure Notion destination-managed snapshots

A `notion` integration is eligible for manual publication only when its
configuration explicitly sets `publication_profile` to
`destination_managed_snapshot_v1`, it has credentials, and it is enabled. A
missing or different value remains connection-only. This profile publishes a
full PDF report and a concise page summary as a new child page below the
configured container. It does not update a prior page: every republish creates
a new snapshot, and the console exposes bounded retained snapshot history.

This is a destination-managed-sharing profile. The Notion workspace owner
controls effective workspace, inherited, guest, and anonymous-link access.
Synapse cannot read or verify the effective ACL. The integration observes a
page's `public_url` where the API exposes it, but a missing `public_url` does
not prove that a page is private. Configure the destination and share the
integration deliberately before publishing; the profile acknowledgement and
the publish action are the only human acknowledgements this workflow requires.

The adapter keeps each page summary to at most 100 blocks and keeps the PDF
attachment at or below 5 MiB so the profile remains usable on free Notion
workspaces. It derives its title, blocks, and upload metadata from the frozen
stored report artifact. The API does not provide a compare-and-swap write for
this flow. Synapse instead fences each current link with its durable revision,
checkpoints acknowledged uploads and blocks, and quarantines an ambiguous remote
write as uncertain. This profile has no automatic reconciliation or Resume action
for an ambiguous write. Preserve its intent and receipts for reviewed operator
recovery; do not clear the command or replay the mutation blindly.

Unpublish moves only the current snapshot page to Notion's recoverable Trash.
Files may persist according to Notion's lifecycle, and Synapse does not claim a
permanent purge. Older snapshots are retained and no automated job removes
them. Notion snapshot destinations are excluded from scheduled delivery; use a
manual publish whenever a new snapshot is required.

## Configure an S3-compatible bucket

Create an enabled `s3-compatible` integration. Its endpoint is the HTTPS S3 API
origin, with no path, query, fragment, or credentials, for example
`https://s3.eu-west-1.amazonaws.com` for AWS or `https://objects.example.com` for
a self-hosted gateway. An `*.amazonaws.com` endpoint is pinned to its own host on
port 443. Any other endpoint must be listed in the deployment's reviewed
self-hosted allowlist, the same rule the self-hosted forge and Confluence Data
Center profiles use.

| Field | Required value |
| --- | --- |
| `space` | The destination bucket name. |
| `prefix` | The key prefix that holds publications, such as `engagement-reports`. |
| `read_group` | The exact reader principal, such as `arn:aws:iam::123456789012:role/report-readers`. A wildcard is refused. |
| `region` | The bucket region used for request signing. |
| `read_endpoint` | Required HTTPS base URL of an authenticated reader gateway mapped to this bucket. |
| `data_class` | `detail`. |

Supply the access key in `access_key_id` and the secret in `secret_access_key`,
both sealed and write-only. `session_token` is optional and holds a temporary STS
token. Synapse does not refresh a temporary credential: record its expiry in your
credential operations and reseal the fields before it expires, because scheduled
releases and restriction checks read the current credential and fail closed.

`read_endpoint` is separate from the S3 API endpoint. It is the reader-facing,
bucket-mapped HTTPS base URL and must serve the published report at
`<read_endpoint>/<prefix>/<marker>/report.html`. Attachments use relative URLs
from that HTML document, so they remain in the same authenticated publication
directory. The gateway operator must authenticate the intended audience, authorize
it for the configured `read_group`, and sign or assume requests using that exact
principal before reading the bucket. Its cache must be purged or revalidated on
unpublish; it must not serve stale report bytes after Synapse has confirmed the
publication prefix is gone.

The destination carries two operator-owned requirements, and Synapse proves both
before a neutral shell, each attachment upload, and the body write:

- **Versioning is enabled.** Version IDs identify exact reads and purge targets;
  they are not S3 PUT preconditions. A bucket with versioning suspended is refused.
- **The bucket policy has a strictly provable reader grant.** The bucket policy is
  the only access authority this profile accepts, because object ACLs are unreadable
  or inert on several S3-compatible implementations. Keep ACLs disabled
  (`BucketOwnerEnforced` on AWS) and express one unconditional `Allow` for the
  configured principal covering the complete publication prefix.

The policy proof accepts only a bounded policy vocabulary: `Allow`/`Deny`, an AWS
principal or `*`, supported object-read actions, and literal object ARNs with at
most one trailing wildcard. It rejects duplicate keys, conditions, `Not*` forms,
variables, unsupported principal namespaces, and unverifiable wildcard resources.
An overlapping `Allow` for `*` or another principal is a lost restriction even when
a `Deny` also exists. Missing, malformed, or otherwise unsupported policy syntax
leaves the reader unproven and refuses the release without claiming a breach; that
distinction is what restriction monitoring reports.

Each publication lives under `<prefix>/<marker>/`. It holds a zero-length
`.synapse-shell` object that carries the marker, the `report.html` body, and the
managed attachments, each stamped with the publication marker in user metadata.
An unstamped or foreign object under that prefix blocks the release. Current-object
listings normally need one HEAD per object to pin its VersionID and verify its
marker, including listings that already contain user metadata. A publication is
bounded to 64 current objects. `space` and `prefix` are the immutable
destination container; do not repoint either after a link has been published.

The opaque document revision is the current body ETag. A new body write uses a
single `If-Match` PUT against that ETag; shell, body, and attachment creation use a
single `If-None-Match: *` PUT. A failed precondition is a definite conflict and no
operation retries a dispatched PUT. This fences changed current bytes, but it is not
a strict VersionID fence: restoring exactly the same bytes restores the same ETag,
so exact-byte ABA is a known limitation. Governed commands serialize each target
and recheck the target fence before each sensitive step.

The current-object listing is capped at 64 objects. New writes are admitted only
while history remains below 192 versions, reserving capacity in the 256-version
purge snapshot. Purge first lists and proves every exact version and delete marker,
including ownership and Object Lock state, before dispatching any delete. At most
four read-only version proofs run concurrently; every proof must finish before
deletion begins. Purge then deletes those exact version IDs and re-lists to confirm the prefix is empty. The
attachment reference inside the body stays relative to the publication prefix, so
the stored HTML never embeds a presigned or public URL.

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
governed removal command. A Notion destination-managed snapshot is moved to
recoverable Trash; that action retains older snapshots and does not claim a
permanent file or page purge. Confluence deletes every attachment, including its trash
or permanent-purge phase, before deleting the page with the same whole-object
procedure. Google Drive deletes only the proven service-owned publication folder
and its managed artifacts; its trash history is not treated as proof of deletion.
SharePoint and OneDrive Business permanently delete only the proven managed body,
attachments, and publication folder. An S3-compatible bucket proves the complete
version snapshot before deleting any exact version or delete marker under the
publication prefix, then re-lists to confirm it is empty; a version held by Object
Lock or a legal hold refuses the purge instead of reporting a removal the bucket did
not perform. A retired link cannot be recreated for that target.

Each worker invocation checkpoints at most one acknowledged remote write and returns
the command to the pending queue. The next invocation continues from the stored
receipts and remote revision. A successful slice does not consume the failure retry
budget. Checkpoint and yield require the same unexpired lease and intent/progress
revisions; caller cancellation permits only a bounded local checkpoint, with no
further provider request.

A timeout, crash, expired lease, partial purge, or ambiguous provider response is
`uncertain`. Synapse does not retry an uncertain operation blindly. It reconciles
the durable marker and requires a unique verified remote result before it can
finish. Drive and SharePoint/OneDrive store the provider's opaque body revision
token alongside the compatible numeric version sentinel; the token is compared
exactly and never converted to, parsed as, or advanced like an integer. A body
write is recovered only when its marker, title, and stored content match and the
opaque token changed from the checkpoint. A 404 never proves a purge. Before deleting, native providers validate the entire
listed ownership set; no delete is issued when any child is unmanaged. Once a
delete is dispatched, later errors retain uncertainty, including a definite 4xx
from a subsequent request. A created attachment whose ACL or ownership-manifest
write cannot be confirmed is also quarantined. A successful restriction mutation
followed by a refused readback keeps its outstanding fence and releases no content.
Keep the
intent and audit history while resolving an uncertain state. Command leases and
intent/progress revisions fence stale workers and concurrent republish or
unpublish operations.

## Sharing after publication

The integrations worker also checks existing, non-retired links. Each tenant tick
claims one due link through an indexed queue, with a twelve-second pass
budget and a ten-second observation budget. The remaining two seconds are reserved
for audit/checkpoint persistence. The 45-second worker pass defers the next tenant
without advancing its rotation when less than twelve seconds remain. A claimed link becomes eligible again
after five minutes if the worker crashes. Verified links are checked again after
15 minutes; lost or unverifiable sharing is checked again after five minutes.
A provider `Retry-After` longer than that interval postpones the next observation
until its minimum delay has elapsed.
These are queue intervals, not a guaranteed freshness bound under provider outages
or a backlog. Inspect the last-check timestamp in the console.

Each tenant pass claims at most one restriction check. For one worker serving one
otherwise idle tenant, a five-second runner cadence permits at most 180 checks per
15-minute interval even with negligible provider latency. This is a scheduling
ceiling, not supported production capacity: publication work, multiple tenants,
provider quotas and slow proofs reduce it. If a proof takes ten seconds, the
single-tenant ceiling falls to 90 checks per 15 minutes before other work. A larger
backlog cannot promise a 15-minute sweep. Track last-check age and due-link backlog;
measure your native provider latency and quota before choosing a deployment size.

In the synthetic Graph contract fixture, a combined restricted read costs
`16 + 2N` requests for `N` inherited attachments, with at most four concurrent
child proofs. A fresh identity-only read followed by a second complete proof costs
`26 + 3N`; sensitive-write guards now use the combined read. With eleven
attachments the direct restriction-only observation made 38 requests in 2.041s
at a synthetic 100ms/request RTT. The old duplicate-read harness made 59 requests
in 3.262s. These fixtures do not establish native latency or a production SLO.
The no-attachment Drive combined-read fixture makes nine sequential requests.
A Graph attachment operation separately makes 32 requests in its fixture; cost
rises with the existing children. Every actual upload/write retains its own fresh
restriction check immediately before dispatch. No proof is cached across writes.

Each executor claim persists a version/lease-bound progress checkpoint before
provider work, including read-only pre-write checks. The PostgreSQL checkpoint
save currently rereads the immutable artifact once; the encoded artifact limit
is 32MiB. Yield and throttle-deferral returns reuse their already locked command
instead of reading it a second time. List and direct execution still perform
fresh reads. These choices preserve fencing and cost memory/JSON decoding for
large reports; [queue measurements](../evidence/remaining-providers/queue-cost.json)
record that bound and the remaining artifact-validation cost.

The sweep reads the page identity and exact restricted-sharing proof using current
destination credentials. For Confluence Cloud it also reads the public-link policy.
It never uploads content or silently changes a remote ACL. A lost restriction
records `document.restriction_lost` and shows **Restricted sharing lost**;
unavailable credentials, disabled connections or unreadable providers show
**Sharing could not be verified** and record `document.restriction_unverifiable`.
After a successful checkpoint, repeated failures do not repeat the event unless the
observed state changes. A crash between the append-only audit write and the
checkpoint can leave another observation event on the next attempt. Audit records
include the observed link revision; concurrent republish, purge and worker claims
fence stale checkpoints.

A remote administrator can still change access between checks. Investigate a
warning immediately, restore the approved restricted destination, and verify the
next check, or request governed unpublish. Every subsequent publish still rechecks
sharing immediately before each sensitive upload. Unknown policy keys, conditions,
duplicate JSON keys and unsupported effects fail closed; they cannot prove an
unconditional public-link block.

## Scheduled delivery

Schedules are available only when PostgreSQL, notifications, a shared vault key,
the API, and an `all` or `integrations` worker are configured. They run weekly or monthly in an IANA
time zone. Weekly `weekday` uses Sunday `0` through Saturday `6`; monthly `day`
uses `1` through `31` and clamps to the last day of shorter months. A nonexistent
DST wall minute advances to the first real minute; an ambiguous wall minute uses
the first occurrence. The selected UTC due instant is stored durably.

Each due occurrence first revalidates the current document destination before it
builds and freezes an artifact. The persisted `confluence` schedule destination is
the legacy API value for every enabled document-publishing profile, including
Google Drive, SharePoint, OneDrive Business, and S3-compatible buckets; the
console labels it **Document publishing**. That validation resolves the current tenant integration, config,
provider capability, and release preflight, so an unsupported destination is
refused before artifact generation. A document schedule uses the frozen
artifact for its command. An email schedule uses the same PDF as an attachment.
The occurrence, content hash, remote page state, and per-recipient delivery
counters are available from
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

Notion's `destination_managed_snapshot_v1` profile is deliberately not a schedule
destination. It requires an explicit manual publication and never creates
unattended snapshot pages.

## Operational evidence

Provider 429 responses persist a separate next-attempt deadline. Read-only
preflight or reconciliation throttles postpone observation without exhausting
write attempts. A clean pre-write checkpoint releases its lease while preserving
acknowledged progress. Partial upload/purge or confirmation failures retain the
uncertain state, outstanding operation and receipts; the deadline delays recovery,
not permission to repeat a write. The retry floor is one minute and a longer
provider `Retry-After` is preserved. Direct execution honors the same deadline as
worker selection. Definite no-effect write refusals keep the existing bounded
failure-attempt policy.

The provider retry-scheduling migration must precede updated binaries. Upgrade all
workers before relying on persisted throttling: old workers ignore the new due
columns. Rollback refuses to remove a future document delay or ticket poll claim.
Disable affected integrations, stop workers and let those deadlines expire before
rollback, or apply a forward repair. Never clear an uncertain operation to bypass
the guard.

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
retain the matching exact group name and space proof. For Drive, retain the exact
folder, service-owner, and group-reader proof. For SharePoint or OneDrive Business,
retain the matching Graph/SharePoint folder binding and exact group/custodian role
proof. Never record API tokens, organization keys, SMTP credentials, recipient
addresses, report body, or PDF bytes in operational evidence.

## Acceptance status

The supported provider profiles have contract tests for their restricted release,
revision, reconciliation, and purge behavior. They are not live acceptance
evidence. End-to-end execution against permitted provider sandboxes is explicitly
deferred for this delivery; no live destination, ACL, or permanent-delete result is
claimed until those resources and a recorded sandbox run are available.
