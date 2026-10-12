# Ticketing foundation

Ticketing provides storage and domain contracts for external tickets. Provider
integrations, routes, UI and outbound writes are future consumers of this foundation.

Mappings attach an existing integration to either one project or one engagement. Links
may attach an HTTPS ticket URL to a finding even when no integration is configured.
Write intents are idempotent by (tenant, integration, request key), while the immutable
correlation marker derives from the intent ID. A replay with different command content
is a conflict, not a second outbound operation.

Opening an intent verifies that its finding belongs to the requested engagement.
A project mapping must match that engagement's authoritative `ProjectID` through
the tenant's project analysis context. `AssessmentProjectID` is a separate visible
assessment association and cannot authorize a project mapping.
The internal `ListLinks` contract returns all links for a finding. Before exposing
it through an API, consumers must introduce bounded pagination or an enforced
per-finding limit; the foundation provides no production cardinality guarantee.

The pure `internal/domain/writeintent` state machine is shared with future
documentation publishing. In-flight lease expiry leads to `uncertain`; this state
must never be submitted again without remote reconciliation. Exactly zero marker
matches permits `reconcile_absent` to return to pending, and exactly one match permits
`reconcile_found` to finalize. `reconcile_multiple` records `multiple_matches` while
keeping the intent uncertain; it cannot be claimed and requires human intervention.
An explicit, definitive provider rejection becomes `failed` and requires a bounded
error classification. Raw provider errors are never accepted as classifications.

Acknowledgement and reconciliation-found transitions require a verified remote
ticket ID and canonical HTTPS URL. Both adapters persist these on the completed
intent and create its finding link in the same transaction or critical section.
A matching provider link is reused. A manual link to the same URL is promoted to
the verified provider identity, retaining its ID and creation time. A conflicting
provider identity aborts completion and leaves both intent and link unchanged.
An explicit later unlink removes the display association; the completed intent
retains the remote identity needed for recovery.

All three tables use tenant-scoped composite foreign keys and
`synapse_enable_tenant_rls`. No provider credentials, outbound URLs with query
parameters, raw transport errors or API changes are stored here. The existing
integration connection and credential core remains the only reused framework part.

Service constructors require a store, finding and engagement readers, ID generator
and clock. The memory adapter requires its parent engagement and finding stores
so missing or foreign finding references fail consistently. Every operation
requires an explicit tenant; a missing tenant fails validation. Both adapters honor
context cancellation and use version checks to permit one successful claim per intent.
The PostgreSQL adapter commits each change in a tenant-scoped transaction; a new
connection reads the same intent and its current state after a restart.

Run the normal migrate-first deployment workflow to install migration `0230` before
using the PostgreSQL store. It adds tables without changing existing integrations.
Roll back application code while retaining these tables if ticket data has been
written. Schema rollback refuses to drop populated ticket tables; after an explicit
data retention decision and removal of ticket records, an empty schema can be rolled
back and installed again. Memory storage is non-durable development persistence;
PostgreSQL also validates references to existing integrations and scopes. A finding
or engagement referenced by a durable intent cannot be deleted; retained intent
history produces a conflict rather than silently discarding remote-write evidence.

The shared store conformance tests cover replay, mismatched commands, cancellation,
tenant boundaries, parent references, concurrent creation and claims, atomic remote
completion, classified rejection and multiple-match reconciliation. PostgreSQL tests
additionally cover unprivileged RLS, reopened connections, retained finding history
and fresh/upgrade/rollback migrations.
