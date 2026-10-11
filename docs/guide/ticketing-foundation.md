# Ticketing foundation

Ticketing provides storage and domain contracts for external tickets. Provider
integrations, routes, UI and outbound writes are future consumers of this foundation.

Mappings attach an existing integration to either one project or one engagement. Links
may attach an HTTPS ticket URL to a finding even when no integration is configured.
Write intents are idempotent by (tenant, integration, request key), while the immutable
correlation marker derives from the intent ID. A replay with different command content
is a conflict, not a second outbound operation.

Future provider consumers must verify a finding's authoritative project association
before using a project mapping. The foundation only checks project existence and
tenant ownership; `ProjectID` and `AssessmentProjectID` remain distinct associations.
The internal `ListLinks` contract returns all links for a finding. Before exposing
it through an API, consumers must introduce bounded pagination or an enforced
per-finding limit; the foundation provides no production cardinality guarantee.

The pure `internal/domain/writeintent` state machine is shared with future
documentation publishing. In-flight lease expiry leads to `uncertain`; this state
must never be submitted again without remote reconciliation. Exactly zero marker
matches permits `reconcile_absent` to return to pending, and exactly one match permits
`reconcile_found` to finalize. Multiple matches require human intervention.
An explicit, definitive provider rejection becomes `failed`.

All three tables use tenant-scoped composite foreign keys and
`synapse_enable_tenant_rls`. No provider credentials, outbound URLs with query
parameters, raw transport errors or API changes are stored here. The existing
integration connection and credential core remains the only reused framework part.

Service constructors require a store, ID generator and clock. Every operation
requires an explicit tenant; a missing tenant fails validation. Both adapters honor
context cancellation and use version checks to permit one successful claim per intent.
The PostgreSQL adapter commits each change in a tenant-scoped transaction; a new
connection reads the same intent and its current state after a restart.

Run the normal migrate-first deployment workflow to install migration `0229` before
using the PostgreSQL store. It adds tables without changing existing integrations.
Roll back application code while retaining these tables if ticket data has been
written. Schema rollback refuses to drop populated ticket tables; after an explicit
data retention decision and removal of ticket records, an empty schema can be rolled
back and installed again. Memory storage is non-durable development persistence;
PostgreSQL also validates references to existing integrations, scopes and findings.

The shared store conformance tests cover replay, mismatched commands, cancellation,
tenant boundaries and concurrent creation and claims. PostgreSQL tests additionally
cover unprivileged RLS, reopened connections and fresh/upgrade/rollback migrations.
