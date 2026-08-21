# ADR 0007 — Paired backup and forward-only upgrades

**Status:** Accepted · **Date:** 2026-08-20 · **Deciders:** Issue #587

## Context

A report is recoverable only when its PostgreSQL records and evidence objects describe the same point in
time. An independent database snapshot and object-store backup can restore a chain that references absent
or newer blobs. Likewise, a schema downgrade after an attempted release can lose or reinterpret durable
records. See [Deployment](../guide/deployment.md) and [Operations drill evidence](../guide/operations-drill-evidence.md).

## Decision

Production backup and upgrade operations use these policies:

- Take a paired, quiesced backup. Drain or stop API and worker writers, wait for in-flight durable work to
  reach a recorded terminal state, then capture the PostgreSQL backup and the evidence-object inventory or
  versioned snapshot from the same quiesced window. Record the UTC window, database backup identifier,
  object-store version/snapshot identifier, application release, migration version, and manifest hashes.
- Restore drills restore the pair together into an isolated environment and verify the evidence and audit
  chains before declaring success. Each drill produces the versioned operations-drill envelope defined in
  [`operations-drill-evidence-v1.schema.json`](../guide/schemas/operations-drill-evidence-v1.schema.json); raw drill
  material remains outside version control.
- Database migration is forward-only. Before a production upgrade, create and validate a paired backup
  copy. If the release must be abandoned, roll back only by restoring that copy and deploying the known-good
  release against it. Do not run down migrations, point an older binary at a forward-migrated production
  database, or treat a Helm rollback as a data rollback.

## Consequences

- Backup automation needs coordinated API/worker quiescing, immutable object versioning or an equivalent
  inventory snapshot, and retention for both halves of the pair.
- Recovery time includes restoring and validating both durable stores; a successful database-only restore
  is not a recovery success.
- Releases require an approved recovery point and enough isolated capacity to test rollback on a copy.
- The migration Job in [ADR 0005](0005-production-helm-eks-topology.md) can move schemas forward but
  cannot provide a downgrade path.
