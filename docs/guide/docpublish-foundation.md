# Documentation publishing foundation

Documentation publishing provides storage and domain contracts for pages that Synapse writes
to an external system. Providers, routes, release control, scheduling and UI are future
consumers of this foundation (EPIC #1327, WS6).

It sits beside the [ticketing foundation](ticketing-foundation.md) and shares its pure
`internal/domain/writeintent` state machine, but it is a separate bounded context with its
own tables. It does not use `integration_operations`, integration bindings, the CI scheduler
or a notification delivery. Only the integration framework's connection core is reused: an
intent names an existing `integrations` row.

## Links and intents

A **link** is the current state of one remote page: its page ID, the remote version Synapse
last wrote, the page URL, the hash of the content it holds, and a `revision` that counts the
writes applied to the link.

An **intent** is one publish or republish attempt. The state machine ends at `done`, and a
`done` intent is never claimed again, so a page that is republished gets a new intent each
time. The link is what persists. Completing an intent writes the link in the same
transaction (PostgreSQL) or critical section (memory); if the link write is refused the
intent is left exactly as it was.

## What a target is

A target is `(integration, source kind, source reference, scope parent, container)` inside
one tenant. Source references are local to their engagement or project: two parents can
publish the same reference into the same container without sharing a link.

| Source kind | Scope | Notes |
|---|---|---|
| `engagement_report` | engagement | rendered on demand |
| `assessment_closure_report` | project | stored per cycle, manifest and renderer version |
| `project_quality_summary` | project | no stored artifact yet |

The source kind fixes the scope; both the domain and a database CHECK refuse a link in the
wrong one. The source reference is a bounded, opaque string that the publisher fills, because
the three kinds are not stored alike. The container is the remote place the page lives in,
for example a Confluence space key. The same artifact published to another container is
another page and another link. A page's parent inside its container is a creation attribute,
not part of the identity.

Scope parents are tenant-scoped composite foreign keys with `ON DELETE RESTRICT`: an
engagement or project that has published documents cannot be deleted from under them.

## Actions

An intent is `create` or `update`.

- `create` makes a page that does not exist. Opening one for a target that already has a link
  is a conflict, because the link means the page exists and a second create would make a
  duplicate page.
- `update` writes a new version of the page of an existing link and must name that link.

Unpublishing is a different remote write with its own reconciliation rules. It is not
modelled here and will add its own action with that work.

## Completion rules

A completed intent carries the remote page ID, URL and version it produced. Against the link
currently stored for its target:

- No link and a `create`: the link is created with the intent's ID, revision 1.
- No link and an `update`: conflict. The link it wrote to no longer exists.
- A different page ID: conflict. A page's identity is never replaced. A second create that
  produced another page stays unfinished for a person to resolve.
- A newer remote version: the link moves forward, with its content hash and `revision + 1`.
- An older remote version: the intent is done, the link is untouched. A write that finished
  after a newer one is history, not the current state.
- The same version with the same content: a replay, nothing changes.
- The same version with different content: conflict.

## Idempotency and uncertainty

Intents are idempotent by `(tenant, integration, request key)`. A replay with the same
content returns the original intent, also after its link exists. The same key with a
different payload digest, content hash, target, action or link is a conflict, not a second
outbound write. The correlation marker derives from the intent ID.

An identical replay also returns the original intent when that command completes between
the replay's initial request-key lookup and its check for an existing link.

An expired in-flight lease leads to `uncertain`, which is never submitted again without
remote reconciliation: exactly zero marker matches permit `reconcile_absent` back to
`pending`, exactly one permits `reconcile_found`, and more than one records
`multiple_matches` and keeps the intent uncertain. A definite provider rejection becomes
`failed` and needs a bounded error classification; raw provider errors are never accepted.

## Listing

`ListLinks` returns the newest links of one scope and requires a limit of 1 to 100. Consumers
page through a bound, not through an unbounded read.

## Storage and rollout

Run the normal migrate-first deployment workflow to install migration `0239` before using the
PostgreSQL store. It adds two tables, `document_links` and `document_intents`, with
`synapse_enable_tenant_rls` and tenant-scoped composite foreign keys, and changes nothing that
exists. Both tables are tenant scoped; every operation requires an explicit tenant.

An intent has no foreign key to the link it wrote to, so the intent, which is the evidence of
a remote write, outlives the link.

Roll back application code while retaining these tables if document data has been written.
Schema rollback refuses to drop populated tables; after an explicit data retention decision
and removal of the records, an empty schema can be rolled back and installed again. Memory
storage is non-durable development persistence.

## Verification

One conformance suite, `internal/testutil/docpublishconformance`, runs against both adapters.
It covers replay and mismatched commands, cancellation, tenant boundaries, scope parents,
concurrent creation and claims, atomic completion for create and update, stale and
contradicting completions, and multiple-match reconciliation. The PostgreSQL tests add
unprivileged RLS, reopened connections, the CHECK and foreign-key guards, and fresh,
upgrade, rollback and re-apply migration runs.
