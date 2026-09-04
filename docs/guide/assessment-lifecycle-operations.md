# Assessment Cycle and Snapshot rollout

Assessment lifecycle rollout is additive and fail-closed. Apply migrations first, enable Cycle dual-write for a bounded tenant allowlist, backfill historical Assessments, verify integrity, and only then enable lifecycle reads and UI.

The API and worker never run historical backfills during startup. Every command below requires `SYNAPSE_DB_DSN` and accepts at most four comma-separated tenant IDs per process.

## 1. Backfill singleton Cycles

Start with a dry run:

```bash
synapse-assessment-backfill \
  --tenants tenant-a \
  --dry-run \
  --batch-size 500
```

After reviewing the projected count, run the write pass:

```bash
synapse-assessment-backfill \
  --tenants tenant-a \
  --batch-size 500 \
  --timeout 2h
```

The command excludes hidden Project analysis contexts and never rewrites or deletes source rows. Each tenant has one leased active run, a frozen source snapshot, and a durable Assessment-ID checkpoint after every committed batch. An expired lease resumes the existing run without creating duplicate Cycles. `--resume-after` is available only for a single tenant.

The default batch size is `500`; the maximum is `2000`. Cancellation is durable. Item records contain stable reason codes and bounded repair guidance rather than raw database/provider errors.

## 2. Backfill legacy Snapshots

Run this only after the Cycle backfill completes:

```bash
synapse-assessment-snapshot-backfill \
  --tenants tenant-a \
  --dry-run \
  --batch-size 500

synapse-assessment-snapshot-backfill \
  --tenants tenant-a \
  --batch-size 500 \
  --timeout 2h
```

The command appends immutable `legacy` Snapshots without changing an Assessment's default Snapshot pointer or rewriting Scan Runs. It prefers verified sealed run manifests. When lane provenance is unavailable it does not invent coverage dimensions; projected legacy coverage remains `unknown`. A changed source creates a new append-only projection, while an unchanged rerun records `already_projected`.

Native Snapshot finalization accepts only tenant-owned Scan Runs whose aggregate and lane manifest hashes recompute correctly. The API selects server-stored run/lane facts; clients cannot submit arbitrary target, version, coverage, or evidence fields.

## 3. Backfill Finding Identity and Observation lineage

Run this only after the Cycle and Snapshot backfills complete. Start with a dry run, review its outcome counts, then run the write pass:

```bash
synapse-finding-lineage-backfill \
  --tenants tenant-a \
  --dry-run \
  --producers sca,sast,quality,reliability,secret,iac,manual,offensive,dast,cloud \
  --batch-size 500

synapse-finding-lineage-backfill \
  --tenants tenant-a \
  --batch-size 500 \
  --timeout 2h
```

The command pages immutable source Findings by ID and writes versioned Identities, immutable Observations, review Candidates, or explicit Skip records. It does not copy workflow, SLA, disposition, assignee, raw evidence, or secret values. Missing semantic anchors become provisional review candidates; unsupported producers receive stable skip reasons instead of fuzzy matches.

Each source row records exactly one `observation_created`, `provisional_candidate_created`, or `skipped` outcome. PostgreSQL enforces the run-level equality `processed = observation_created + provisional_candidate_created + skipped`, one leased run per tenant, tenant RLS, composite ownership, and lease-token fencing for resume safety. The default batch size is `500`, the maximum is `2000`, and one process accepts at most four tenants.

## 4. Verify integrity

Run the read-only verifier after both write passes:

```bash
synapse-assessment-integrity \
  --tenants tenant-a \
  --dry-run \
  --batch-size 500
```

`--dry-run=false` is rejected. The verifier checks coverage, root/member shape, frozen boundaries, selected-head eligibility, Re-test allocation, predecessor integrity, graph acyclicity, and source/checkpoint reconciliation. Findings are persisted under tenant RLS and emitted as JSON lines with stable reason/severity codes and deterministic repair plans. Any finding causes a non-zero exit and must be resolved before read cutover.

## 5. Canary and cut over reads

For each tenant, record the deployment revision, enabled flags, backfill run IDs, integrity run ID, approver, start/end timestamps, and rollback result.

Use this order:

1. Apply lifecycle migrations `0131` through `0137` after the Scan Run provenance migration from PR #779.
2. Enable `SYNAPSE_ASSESSMENT_CYCLE_DUAL_WRITE_ENABLED` for an internal tenant allowlist.
3. Confirm new initial Assessments atomically create a Cycle and root member.
4. Run the Cycle and Snapshot backfills, then the Finding lineage backfill and integrity verifier.
5. Enable `SYNAPSE_ASSESSMENT_SNAPSHOT_ENABLED`.
6. Enable `SYNAPSE_ASSESSMENT_IDENTITY_COMPARISON_SHADOW_ENABLED` for a verified tenant allowlist and monitor the bounded Lineage metrics.
7. Enable `SYNAPSE_ASSESSMENT_LIFECYCLE_READ_ENABLED` for the verified tenant allowlist.
8. Enable `SYNAPSE_ASSESSMENT_LIFECYCLE_UI_DEFAULT_ENABLED` only for tenants already enabled for lifecycle reads.

## Rollback

1. Remove the tenant from `SYNAPSE_ASSESSMENT_LIFECYCLE_UI_DEFAULT_TENANTS` and deploy.
2. Remove it from `SYNAPSE_ASSESSMENT_LIFECYCLE_READ_TENANTS` and deploy.
3. Disable Snapshot and dual-write gates if the incident requires write rollback.
4. Do not delete source Assessments, Scan Runs, Cycles, members, or Snapshots.
5. Verify `/api/v1/me` reports lifecycle read/UI as false, lifecycle routes fail closed, the sidebar is hidden, and legacy Engagement reads still work.

Rollback migrations deliberately refuse to drop populated immutable lifecycle state. Preserve it for audit and repair.
