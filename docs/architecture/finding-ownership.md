# Finding ownership foundations

The ownership domain routes a canonical finding to one accountable team and
records the source evidence behind that decision. Team membership is a grouping
of existing users; it grants no role or engagement access. An individual still
claims or receives a finding through the existing human triage workflow.

This document describes the domain and PostgreSQL foundations. Producer capture,
worker dispatch, HTTP routes and UI are separate integration milestones and are
not enabled by the foundation migration. No existing finding is reassigned when
an application applies migration 0164.

## Identity and resolution contracts

`ownership.Team` has a tenant-local slug, immutable ID, optimistic revision and
archive flag. Membership references existing users. The generated
`users.ownership_tenant_id` column normalizes an empty legacy tenant to `default`
for composite foreign keys without changing the original `users.tenant_id` value.
Disabled users cannot receive new assignments, and readonly membership does not
allow claiming work. Archived teams remain available in history.

An owner mapping binds an exact repository identity and CODEOWNERS token to a
Synapse team. An optional suggested user must belong to that team. No username,
email or SCM team lookup happens implicitly. Mutable mapping drafts are copied
into an immutable policy version; later mapping edits do not change old decisions.
Business-asset mappings reference `fleet_business_services`, the existing business
asset model, rather than treating its free-text `Owner` as a validated user/team ID.

Resolution order is manual protection, ordered explicit rule, CODEOWNERS, then
business-asset fallback. Lower rule priority wins; duplicate priorities are invalid.
Conditions within a rule are ANDed, entries in each list are ORed. A path rule
must cover every relevant path, so one manifest cannot hide a second manifest
introducing the same vulnerable dependency. Explicit exclusions, partially mapped
owners and incomplete path ownership stop fallback and retain their explanation.
Different candidate teams produce `ambiguous`; there is no arbitrary tie breaker.

A policy scope is one engagement plus an optional repository identity. An active
repository-specific policy wins over the engagement-wide active policy. The
database uniquely identifies each scope. Activating or creating a policy takes an
exclusive engagement policy-scope lock; routing commits take the shared lock and
recheck the winning policy. A newly activated specific policy cannot race an old
fallback decision into storage. Policy contents and their mapping snapshot hash
are immutable; active-version changes use a separate policy revision.

## Source trust and bounded matching

`ownership.Snapshot` stores exact CODEOWNERS bytes, their SHA-256, selected path,
parser version, repository and engagement identity, resolved source revision and
approval metadata. Source revisions use `git:<40-or-64-hex-object-id>` or
`sha256:<64-hex-archive-digest>`; moving branch names are rejected. The scan source
revision is recorded separately from the trusted ownership revision. A PR scan
must use an approved base snapshot rather than a contributor-controlled head.

The parser follows GitHub CODEOWNERS file precedence and last-match semantics.
An empty higher-priority file is still selected. Multiple and empty owners,
case-sensitive paths, anchored paths and directory/glob matching are supported.
Unsupported syntax and invalid tokens produce line-numbered diagnostics; a
snapshot with diagnostics requires explicit acceptance before activation.
See [GitHub's CODEOWNERS specification](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).

Bounds are 3,000,000 source bytes, 20,000 non-comment entries, 100 owners per line, 4,096 bytes
per path, 128 relevant paths per finding, 200 routing rules and 200 conditions per
rule. Resolution additionally bounds path bytes multiplied by compiled pattern
count to 20,000,000, returning a saturation error instead of partially evaluating
an excessive document. Capture adapters must reject unsafe filesystem paths and
symlinks; the domain normalizes relative separators and rejects traversal, drive
paths, UNC paths and NULs without filesystem access.

The resolver freezes its policy inputs and sorts/deduplicates relevant path and
identity sets before hashing. Machine-owned finding versions/timestamps are not
routing fingerprints. Manual generation and policy/source content identify replay
boundaries. Relevant SCA paths must be application manifests or introducing direct
dependency provenance for the exact scan, not paths inside third-party packages.

## Assignment and durable handoff

`ports.OwnershipRepository` requires a tenant-bound context on every operation and
participates in `TenantTransactionRunner`. The PostgreSQL adapter checks IDs with
composite foreign keys and forced RLS; it also validates current team/user
eligibility during writes. HTTP/use-case integration must additionally enforce
the caller's existing engagement authorization on reads, lists and mutations.

The effective assignment has at most one team, an optional canonical user, the
legacy assignee mirror, mode, revision and manual generation. An existing free-text
assignee is preserved and treated as protected without guessing its identity.
Assign, claim and clear create manual protection; clear does not release it.
`release` explicitly removes the individual assignment, returns to auto mode and
commits a routing intent. A worker cannot overwrite a manual assignment, even if
it reloads the latest finding version. Drift between the legacy field and an
existing ownership projection also fails closed until reconciled.

`ApplyAssignment` locks the job when routing, then the finding, policy scope,
policy and eligible owners. It checks finding/ownership revisions, manual generation,
active policy and current job fence. The transaction commits all of the following:

1. The assignment projection and legacy finding assignee/version when changed.
2. An immutable decision keyed by the logical transition, with before/after values.
3. A durable notification intent for an effective owner/assignee change, or a
   suppressed intent when notification delivery was disabled for that transition.
4. A routing intent on explicit release, when applicable.
5. The existing hash-chained audit append as the final database operation.

An audit/outbox failure rolls back the entire transaction. The transition key
recovers committed work after a lost acknowledgement; reuse with different
actor/target/evidence fails. Job redelivery does not create another decision,
audit entry or intent. A reevaluation with unchanged assignment does not increase
the assignment/finding version or enqueue another notification. Suppressed intents
cannot be acknowledged as pending delivery and are not resurrected by replay.

The new intent table stores source obligations, not a second execution queue.
Execution will use the existing `JobQueue` and `ownership.route` kind. The source
publisher must publish/enqueue and acknowledge an intent in one bound transaction,
with audit last. Network delivery remains the existing notification framework's
at-least-once contract.

Preview/reroute run records pin a candidate version/hash, policy revision, cutoff,
filter and total count. Preview items are immutable and paginated. Batches contain
at most 100 items; duplicate identical items do not inflate counters, conflicting
items roll back the batch, and a run cannot complete before all selected items are
accounted for. Persisting preview items never writes assignments or notifications.
Run execution and authorization belong to the subsequent worker/use-case milestone.

## Producer and assignment inventory

The following inventory was verified against `94abbfec` on 2026-09-11. Integration
must cover every row; a foundation repository alone does not provide this coverage.

| Producer / write path | Existing boundary | Integration obligation |
| --- | --- | --- |
| Manual and attributed creation | `internal/usecase/findings/service.go`, `Create` / `CreateAttributed` / `withCreationBoundary` | Append a durable intent with the canonical ID inside the creation transaction. |
| Confirmed threat, SAST and DAST judgments | Same service, `RecordConfirmedThreat`, `RecordConfirmedSAST`, `RecordConfirmedDAST` | Capture projection mode and source/asset provenance; retain projection-claim idempotency. |
| Normal source/image/SBOM scan | `internal/usecase/sca/service.go`, `runPipeline` | Resolve dedup-preserved finding IDs after upsert; capture source ownership before workspace cleanup and publish only after its immutable binding exists. |
| Imported SBOM scan | Same service, `runImportedSBOMPipeline` | Bind the imported scan/manifest provenance; mark unavailable source paths explicitly. |
| Vulnerability projection | `internal/usecase/vulnerabilityprojection/service.go`, `Project` | Reuse canonical IDs; capture routing-relevant provenance changes without treating every scan version as an owner change. |
| CSPM findings | `internal/usecase/cspm/service.go`, standard findings upsert | Use explicit engagement/asset mapping when no source path is available. |
| Exploitation findings | `internal/usecase/exploitation/service.go`, findings upsert | Preserve evidence/status semantics and capture asset associations. |
| Engagement transfer | `internal/usecase/transfer/service.go`, findings upsert | Treat destination IDs/scope as new inputs; do not copy a source tenant/team relationship blindly. |
| Writeup updates | `findings.Service.ApplyWriteupDraft` | Description-only updates must not trigger ownership changes. |
| Manual assignee endpoint | `finding_handler.go` → `findings.Service.SetAssignee` → `FindingRepository.SetAssignee` | Replace the separate assignment/audit writes with the common transactional ownership boundary when enabled, including explicit clear protection. Preserve the existing API contract. |
| Finding promotion | `postgres/promotion_store.go`, `Apply` | Promotion changes an existing canonical finding's state/evidence; reroute only if authoritative routing inputs change. |
| Imported findings and project issues | `importedfinding_repo.go`, project issue stores | These are separate entities. No ownership relationship until a verified canonical finding binding exists. |

`FindingRepository.Upsert` is the sole production SQL insert into `findings` in the
audited baseline and preserves existing human assignees on conflict. Its existing
`SetAssignee` is the SQL assignee update path. Producer integration should centralize
capture at these boundaries where possible and use explicit source readiness,
bounded durable reconciliation and stable fingerprints for delayed provenance.
Do not add a callback after commit that can lose work on a process crash.

`sca.Service.captureProjectSource` currently runs before deferred source cleanup,
after the scan readers; comparison capture separately reads base files. Project
source publishing also applies `sourcepolicy.RetainPath`. Therefore ownership must
capture a dedicated bounded CODEOWNERS snapshot at acquisition/capture time and
must not assume a code-viewer manifest retained every ownership file. Durable
`scan_source_bindings` and `engagement_source_packages` remain authoritative for
source associations and archive digests. Deleting retained source must not delete
snapshots referenced by policies/decisions.

## HTTP contract for the integration milestone

The planned `/api/v1/ownership` routes use existing authentication and error
envelopes. They are not registered in this foundation change. Only implemented
routes should be added to `api/openapi.yaml`, together with the HTTP coverage tests.

| Resource | Request/response shape and concurrency |
| --- | --- |
| Teams | `id`, `slug`, `name`, `archived`, `revision`, timestamps; mutations require expected revision. Members reference `user_id` only. |
| Mappings | Exact repository/owner token, `team_id`, optional `suggested_user_id`, revision. Asset mappings use `asset_id`. Policy versions freeze copies. |
| Snapshots | Metadata, content hash, source revision, diagnostics/trust status; raw capture/import is admin-only and bounded. No tenant authority from JSON. |
| Policies | Ordered `rules`, immutable `version`, frozen `mappings`/`assets`, `snapshot_id`; activation requires `expected_revision`, candidate `version` and `expected_hash`. Version zero deactivates. |
| Preview/reroute runs | `id`, `mode`, `state`, revision, policy hash/revision, cutoff, counters and paginated item results. Reroute is a separate explicit operation. |
| Finding ownership | Current team/user/legacy value/mode/revisions, resolution/reason, candidate evidence and paginated decision history. |
| Claim/assign/transfer/clear/release | Explicit action; `expected_finding_version`, `expected_revision`, `expected_manual_generation`, idempotency key and target IDs where applicable. Actor comes from the authenticated principal. |
| Bulk mutations | At most 200 individually authorized items; each item is atomic and returns success/conflict/forbidden separately. |

Use `404` for tenant-inaccessible resources, `409` for stale revision/changed preview,
and existing validation/forbidden responses otherwise. Cursors sort by stable ID;
history uses `(created_at,id)` descending. Default page size is 100, maximum 200.
Counts and lists must apply the same engagement visibility as individual reads.
API keys/member settings remain intact; a team membership is never an access grant.

## Deployment and validation

Apply additive migrations before new binaries; activate routing only after every
API/worker process supports the feature. The eventual capability defaults off,
offers observation/preview without mutation, and enables enforcement per scope.
Memory mode must report unavailable rather than claim durable routing. Historical
reroute remains explicit. Existing assignee writes are unchanged until the common
boundary is wired; do not enable workers before that integration is complete.

Migration tests call the real `Migrate` entry point for both an empty database and
an upgrade from 0163 containing legacy identities/findings. Repository tests use a
separate runtime role with no table ownership, superuser or BYPASSRLS privileges.
They exercise row/FK isolation, immutable evidence, atomic failure injection,
claim contention, stale fences/policies, suppression and preview counters. The
isolated migration helper supports base version zero so fresh-install tests do
not skip the first part of the production migration path.

The preparatory baseline (`94abbfec`) passed Go build/vet and frontend
typecheck/build. Its full Go suite failed on this Windows host in
`infrastructure/blob` (directory sync/symlink privileges),
`infrastructure/sourceupload` (directory sync), and
`usecase/sca.TestAssessmentIaCMixedScanPersistsAllFamiliesAndNeverInfersFixed`
(mixed native IaC coverage). Those failures were captured before this change.
They are not evidence that new ownership checks pass; run the ownership tests
separately with PostgreSQL enabled and report their actual result.

A public title/body review on 2026-09-11 covered 336 issues and 634 pull requests
using CODEOWNERS, finding ownership, team routing, auto-assignment and team-inbox
terms. Matches were dependency-release notes in PRs 3, 4 and 6; no same-scope feature
was found. This does not cover private branches or all comments. Recheck the
[issue tracker](https://github.com/KKloudTarus/synapse-ce/issues) and
[pull requests](https://github.com/KKloudTarus/synapse-ce/pulls) before publication.
