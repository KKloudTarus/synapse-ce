# Ticketing foundation

Ticketing provides storage and domain contracts for external tickets. The
[Jira workflow](jira-ticketing.md) composes these contracts with provider adapters,
routes, UI and durable outbound writes.

Mappings attach an existing integration to either one project or one engagement. Links
may attach an HTTPS ticket URL to a finding even when no integration is configured.
Write intents are idempotent by (tenant, integration, request key), while the immutable
correlation marker derives from the intent ID. A replay with different command content
is a conflict, not a second outbound operation.

Opening an intent verifies that its finding belongs to the requested engagement.
A project mapping must match that engagement's authoritative `ProjectID` through
the tenant's project analysis context. `AssessmentProjectID` is a separate visible
assessment association and cannot authorize a project mapping.
Finding responses return the latest 100 links and intents. Mapping queries filter
the authoritative scope before applying their bound.

The pure `internal/domain/writeintent` state machine is shared with future
documentation publishing. In-flight lease expiry leads to `uncertain`; this state
must never be submitted again without remote reconciliation. The pure
`reconcile_absent` event permits a return to pending, but Jira search can lag:
zero matches retain uncertainty until an administrator explicitly acknowledges
duplicate risk in an audited retry. Exactly one verified match permits
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

## Native ticket destinations

Ticket destinations are registered integrations with the `tickets` capability. Their
outbound IDs are deliberately separate from inbound forge integrations: GitHub Issues
is `github-issues` and GitLab Issues is `gitlab-issues`. The existing `github`
integration remains the inbound webhook provider; it does not become an outbound ticket
destination.

GitHub Issues accepts only a private repository with Issues enabled and a connector
identity that has push, maintain, or admin repository access. GitLab Issues creates
only confidential issues and requires project access. Both providers use the existing
tenant- and forge-host-scoped SCM connector credential. Ticketing never stores a second
GitHub or GitLab credential. SaaS requests use the documented API origins; a
self-hosted connector can be used only through its validated API base and the
operator's host and private-network rules. Repository/project privacy and access are
rechecked before each outward write. A connector change between that check and the
write fences the intent as `credential_changed` without sending the request.

Azure Boards requires a `dev.azure.com/{organization}/{project}` endpoint, a work-item
type, and a sealed PAT. ServiceNow requires a SaaS instance endpoint, a sealed API
token, and either the `incident` or `sn_vul_vulnerable_item` table. Linear requires
`https://api.linear.app/graphql`, a team ID, and a sealed API token. These credentials
are write-only configuration: they are sealed at rest, omitted from API responses and
audit data, and redacted from request/error handling.

Native providers serialize their exact request body during Preview. Synapse persists
that wire payload, its digest, and a code-owned correlation-marker location; Submit
only adds the marker to that frozen payload. A worker never rebuilds a payload from
current finding data. Native mappings use their discovered visibility policy
(`private_repository`, `confidential_issue`, or `provider_access`) and do not permit a
waiver. Grouping, status transitions, Jira labels, priority mappings, components, and
custom Jira fields are rejected for these providers because their serializers do not
support them.

Polling and reconciliation are read/propose-only. A terminal remote state can create a
reviewable local proposal, but it never changes a finding's triage or status directly.
Marker recovery is bounded and verifies provider-specific privacy, project/team, and
marker facts before it can settle an uncertain create. A missing, incomplete, malformed,
or duplicate search result remains uncertain rather than authorizing another write.

The ticket metadata endpoint is `GET /api/v1/integrations/{integrationID}/ticket-metadata`.
It returns the discovered destination, type, native visibility policy, and explicit
support flags. It is the provider-neutral alias; the existing `jira-metadata` route
remains for Jira callers. Managing native mappings is available at
`/settings/integrations/tickets`; the UI shows loading, empty, provider-error, and
permission-denied states and does not offer controls that the selected provider does
not support.

Focused adapter and workflow tests cover native request construction, privacy checks,
credential rotation fencing, marker recovery, and tenant boundaries. End-to-end runs
against live provider sandboxes are deferred; no live-provider acceptance is claimed
without separately recorded sandbox evidence.
