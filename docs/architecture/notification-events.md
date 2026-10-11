# Core notification event capture

Finding creation, status changes and retests commit the business mutation, audit
and notification intent in one tenant transaction. Bulk imports do not emit a
notification for each finding. Creation uses the persisted canonical finding ID;
status and retest events identify the winning version or append-only retest.

Terminal runs and risk acceptance transitions capture at their persistence
boundary. Terminal replay cannot replace the first captured outcome or its
notification facts. Producers store allowlisted, bounded display facts and trusted
subject/user identities before commit. Projection never reads mutable finding,
engagement or run rows to reconstruct these events.

Capture version 3 stores a complete immutable snapshot in the existing source
outbox. Versions 1 and 2 retain their deployed behavior. New workers drain version
3 with a transaction-local capability; source facts cannot be changed by marking
the source processed. Publication, matching, delivery jobs and the processed marker
share one transaction, so a crash before projection is recovered by a later poll.

SLA breach and acceptance expiry use durable episodes. Acceptance identity follows
the human transition, independently of assessment refresh. Warnings are eligible
before expiry; expiration begins at the exact expiry instant. Scheduler state and
its captured event commit together under tenant serialization and lifecycle locks.
Preactivation history is suppressed. Human channels format UTC facts in the tenant
time zone; webhook timestamps remain UTC.

Delivery uses the existing EventSpec, builder, data-class filter, template catalog
and channel adapters. Each event has English and Vietnamese defaults, schemas,
fixtures, context and render goldens. Client evidence is a separate acceptance
step: this implementation does not claim live provider/client validation.

Run migrations first. Quiesce every old notification delivery worker and wait
for its in-flight jobs to finish before starting the upgraded worker fleet. Then
upgrade API producers. Old delivery builders do not understand the new lifecycle
relevance checks, so overlapping old and new notification workers is unsafe.
For binary rollback, keep a capable notification worker running or pause
notification delivery jobs. Pending snapshots require a capable projector;
do not remove them or rewrite emitted identities.
Schema rollback refuses outstanding new captures and rules using new filters or
lifecycle team scopes. CSPM provider identities are saved with the queued run;
an upgrade can recover them from an existing tenant-local job's approved scopes.

Polling reserves lifecycle observation capacity alongside snapshot recovery.
Tenant turns rotate with a bounded share, and a durable category cursor rotates
breach, expiry and each warning window, including small batches. A separate
reserved, rotating turn keeps deployed notification sources progressing under
continuous snapshot traffic. Activation
uses set-based state writes while locking lifecycle rows against human transitions.
Acceptance closes a breach episode; its expiration starts another at expiry.
Human revocation resumes the original deadline and its elapsed reminder backoff.
Queued alerts from an episode closed by acceptance or remediation remain stale.
