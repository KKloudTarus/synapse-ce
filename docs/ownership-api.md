# Finding ownership API

Set `SYNAPSE_OWNERSHIP_MODE=observe` or `enforce` on a PostgreSQL-backed API to
enable team administration, manual ownership and the inbox. The default is
`off`; any other value prevents startup. Apply migrations through 0166 first.
Authentication and Acceptable Use Policy acceptance follow the normal API rules.
The complete request and response contracts are in [OpenAPI](../api/openapi.yaml).

The production source capture and routing worker are still pending. At this
checkpoint, both modes allow manual triage; preview, historical reroute and
release to automatic routing return `503`. Activation records policy configuration
without scheduling work. Check `GET /api/v1/ownership/capabilities` before showing
worker-dependent controls:

```json
{"enabled":true,"mode":"observe","routing_available":false,"reason":"worker_not_configured"}
```

With ownership off, the reason is `disabled`. Memory storage reports
`postgres_required`. Both return `enabled:false` and omit all ownership data routes.
The general `/api/v1/capabilities` catalog also contains the `ownership` entry.

## Access and pagination

Tenant authority comes from the authenticated principal. An empty legacy user
tenant resolves to `default`. Team membership never grants a role or visibility.
Every operation rechecks the stored user role and disabled state. Resources in
another tenant and internal project/host scan engagements return `404`; inbox
rows and totals exclude those internal contexts as normal engagement reads do.

| Permission | Operations |
| --- | --- |
| Human view roles | Teams/members, inbox, current ownership and decision history |
| Existing triage roles | Assign, claim, transfer, clear, release and bulk assignment |
| Admin | Team/membership mutations, mappings, snapshots, policies and runs |

List endpoints accept `limit` (default 100, maximum 200) and an opaque `cursor`.
Follow `next` while preserving the path, filters and authenticated user. Cursors
from a different scope return `400`. Configuration lists can return an empty
final page; inbox pages include the total matching count independent of the cursor.
History sorts newest first by `(created_at,id)`; other lists sort by stable ID.
Unknown or duplicate query filters, unknown JSON properties and extra JSON values
are rejected. IDs and idempotency keys are bounded to 200 bytes at the API boundary.

## Administration

All paths in this table are relative to `/api/v1/ownership`.

| Resource | Operations and concurrency |
| --- | --- |
| `/teams`, `/teams/{id}` | GET/POST and GET/PATCH. Creation uses revision zero; update sends the current positive `revision`. Use `archived:true` to archive. |
| `/teams/{id}/members`, `/teams/{id}/members/{user_id}` | GET and PUT/DELETE. Send the current team `revision` in the mutation body. Membership and revision changes commit together. |
| `/mappings` | GET with required `engagement_id` and `repository`; PUT/DELETE with `engagement_id`, `mapping` and `revision`. The mapping contains the exact repository, owner token, team and optional suggested user. |
| `/asset-mappings` | GET/PUT/DELETE. Bodies contain `mapping:{asset_id,team_id}` and `revision`. |
| `/snapshots`, `/snapshots/{id}` | GET/POST and GET. Lists require `engagement_id`; POST imports bounded CODEOWNERS content. Responses contain metadata; individual responses also include diagnostics, never raw source. |
| `/snapshots/{id}/approve` | POST with `content_hash` and `accept_diagnostics`. Creates a new immutable admin-approved snapshot and returns its new ID. |
| `/policies`, `/policies/{id}` | GET/POST and GET. Lists require `engagement_id`; create includes immutable version 1. |
| `/policies/{id}/versions`, `/policies/{id}/versions/{version}` | POST and GET. Version creation freezes rules, mappings, assets and the snapshot reference. |
| `/policies/{id}/activate` | POST with `version`, current header `revision` and version `content_hash`. A stale header or hash returns `409`; version zero deactivates without deleting history. |
| `/policies/{id}/preview`, `/policies/{id}/reroute` | POST with `version`, `policy_revision`, `policy_hash`, `filter` and an `Idempotency-Key` header. Admission requires the production worker; currently returns `503`. |
| `/runs/{id}`, `/runs/{id}/items`, `/runs/{id}/cancel` | GET progress, GET paginated results, POST cancellation with current run `revision`. Scope authorization includes the parent engagement. |

New mapping records start at revision 1. An update supplies the next revision;
deletion supplies the current revision. Team update and activation instead supply
the current revision. Fetch the record again after a conflict.

Snapshot imports require a pinned `source_revision` (`git:<40 or 64 hex>` or
`sha256:<64 hex>`), repository identity and one of `.github/CODEOWNERS`,
`CODEOWNERS`, `docs/CODEOWNERS`. The server computes the hash and parser version.
Content is limited to 3,000,000 bytes (4 MiB HTTP body); imports start untrusted
unless the admin explicitly supplies `approve:true`. This creates `admin_import`
trust. An API caller cannot manufacture `base_ref` provenance. Diagnostics must
be explicitly accepted before a policy using unsupported syntax can activate.

## Inbox and manual ownership

`GET /api/v1/ownership/findings` supports `engagement_id`, `team_id`, `assignee_id`,
`mine`, `my_teams`, `unresolved`, `severity`, `status`, `kind`, `sla_status` and
`due_before` (RFC3339). `unresolved=true` selects the unresolved resolution,
including findings not evaluated yet. `mine=true` uses the authenticated user ID;
free-text legacy names do not become canonical users. SLA lifecycle status and
deadlines come from the existing persisted SLA assessment, without recalculation.

Read `/api/v1/engagements/{id}/findings/{fid}/ownership` for current ownership,
finding version, ownership revision and manual generation. POST to the same path
with a fresh `Idempotency-Key` and those observed concurrency values:

```json
{
  "action": "claim",
  "team_id": "payments-team",
  "finding_version": 7,
  "ownership_revision": 3,
  "manual_generation": 1
}
```

Claim always targets the authenticated triage user and requires membership in
the current active team. Assign takes explicit team/user IDs. Transfer takes a
destination team and preserves the current assignee when eligible there. If they
are ineligible, or only a legacy free-text owner exists, select an eligible
`assignee_id` or send `clear_assignee:true`; otherwise transfer returns `409`.
Clear removes team and assignee while retaining manual protection. Only release
explicitly removes that protection and requires a configured routing worker.
Disabled users and archived teams cannot receive new assignments.

Each successful transition atomically persists the finding projection, decision,
audit and any notification obligation. Read `.../ownership/history` for the
immutable before/after and resolution evidence. An unchanged effective assignment
creates no new notification. Notifications can be disabled independently; the
transition remains audited and its notification intent is suppressed.

The existing `PUT .../assignee` endpoint keeps its free-text response and optimistic
version contract. Every successful write, including an empty-to-empty clear,
advances the finding version and protects it from automatic routing. Free text
is never looked up as an identity. Audit failure rolls the whole write back.

## Bulk requests and retry

`POST /api/v1/ownership/bulk` accepts `{"items":[...]}` with at most 200 distinct
engagement/finding pairs. Each item has the assignment fields above plus explicit
`engagement_id` and `finding_id`. The request requires `Idempotency-Key`.

A durable reservation binds the caller, key and exact ordered parsed input before
any item is applied. Reusing the key for changed input returns `409`. Items are
individually authorized and committed: HTTP `200` contains a status for each item
(`200`, `400`, `403`, `404`, `409` or `503`). Inaccessible items contain no decision
or finding title. A malformed request is rejected before any item is applied.

After a network failure or server error, retry the same body and key. Completed
items recover their original decisions; unfinished items are checked again, so
their result can change as permissions or revisions change. Reserve a new key
for a revised request. Audit and reservation records currently have no automatic
retention cleanup; a migration rollback dropping 0166 also drops its reservations.
