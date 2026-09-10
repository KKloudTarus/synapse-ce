# Assessment lifecycle rollout operations

Assessment lifecycle rollout is additive and fail-closed. Apply migrations first, enable new-Assessment dual-write for a bounded tenant allowlist, backfill historical Assessments, and keep lifecycle reads disabled until the integrity verifier reports clean results.

## Using the lifecycle

- **Re-scan:** run another scan while the Assessment is not completed. It adds a
  finalized Snapshot to the same Engagement; it does not create a Cycle member.
- **Re-test:** complete the predecessor, then use Create Re-test in an open Cycle.
  This creates a new Engagement with the same frozen Asset/visible Project boundary
  and an explicit predecessor. No per-Finding selection is required. Creating from
  the selected head advances it; creating from another completed member branches
  without changing the selected head.
- **Uploaded source:** use the selected predecessor's current archive (the default),
  or upload another ZIP/TAR revision for the new Re-test. Both choices copy the
  frozen scope and leave the predecessor's source and history unchanged.
- **Authorization:** the compact Create Re-test drawer saves an automatically named,
  non-executable draft. Configure its own authorization window and allowed tool
  classes before scanning. Planned date is planning only. Previous authorization,
  RoE and scanner profiles are never inherited implicitly.
- **Compare:** choose two finalized Snapshots. Ordered snapshots/ancestry permit
  lifecycle classification; reverse or sibling pairs require neutral diff. Missing,
  partial, unknown or changed detection coverage is never evidence of Fixed.
  Finding-level verification remains a separate workflow.
- **Close/reopen:** reviewers use signed, expiring preview/commit commands. Closure
  freezes the root-to-selected-head path and generates a JSON report. Reopen
  supersedes the old manifest; it does not rewrite or remove its report/history.

## Uploaded-source lifecycle

An Assessment owns at most one immutable source package. Initial source upload
accepts a non-empty `.zip`, `.tar`, `.tar.gz`, or `.tgz` archive up to 512 MiB
compressed. Create & Scan attaches it and requests a scan, subject to the usual
scope, authorization and execution gates. Re-scan uses that same package; there
is no replace-source action on an existing Assessment. To test another revision,
complete the Assessment and create a child Re-test in the same open Cycle.

Both Re-test entry points offer the following choices when the selected predecessor
has uploaded-source scope:

- **Use current source** reuses the exact verified bytes attached to that predecessor,
  not the Cycle's root or selected head. It requires no file selection. The new
  Assessment gets its own source version and association; filename, size, SHA-256,
  original uploader and upload time remain unchanged.
- **Upload new source** requires a valid archive and attaches it only to the new
  Assessment. It has its own version, digest and upload attribution. The Cycle's
  source namespace remains stable for supported comparison; a changed digest alone
  is not proof that a Finding is Fixed.

Uploaded-source Re-tests must copy scope; empty scope cannot be combined with
either source choice. Changing the selected predecessor clears the previous file
and source selection, and a failed source lookup must be retried before submission.
Linked Git repositories, local targets and container images retain their existing
flows without uploaded-source controls. Creating a Re-test draft does not start a
scan or inherit execution permission.

For API clients, `source_strategy` is `reuse_current` or `upload_new`. Reuse can pin
the selected predecessor's `source_version_id`; a mismatch returns a conflict
instead of selecting another version. A new file uses multipart upload and must not
be combined with `reuse_current`. The response's `source_selection` records the
chosen strategy and resulting version. Source metadata keeps `uploaded_by` and
`uploaded_at` as original attribution; `associated_by`, `associated_at` and
`reused_from_version_id` describe a later reuse without rewriting that attribution.

### Scan history and audit

Source metadata is pinned when the scan is enqueued, retained with the job, and
sealed into the run manifest. The run-history UI displays that run's `source_package`
(filename, size, SHA-256, version and attribution), never the Assessment's current
metadata as a substitute. Legacy runs without retained source metadata show
**Source metadata unavailable**; no archive identity or upload type is invented.
The Re-test creation audit includes the source strategy, version, digest and reuse
relationship. Internal object keys and filesystem locators are not exposed in the
source or run API views.

### Storage, upgrades and unavailable archives

Use PostgreSQL for durable metadata and either shared S3/MinIO storage or a
persistent filesystem source root. With no `SYNAPSE_BLOB_ENDPOINT`, uploaded source
uses `SYNAPSE_ENGAGEMENT_SOURCE_DIR`, not the temporary extraction workspace or the
development evidence store. API and worker processes must access the same retained
objects. See the [artifact-store configuration](configuration.md#shared-artifact-store-s3-or-minio)
for defaults and shared-volume requirements. Back up metadata and archive objects
together; changing the configured root or bucket does not move existing objects.

If a commit or durable-reference check has an unknown result, cleanup conservatively
retains the uniquely written archive: deleting it could remove committed source or
historical bytes. There is no automatic garbage collection for these uncertain
objects. Before any manual cleanup, an operator must reconcile the write outcome
and verify tenant ownership and all durable references. Never purge source objects
blindly based on a failed request or an archive's age.

Apply migration `0159` (tenant-owned, immutable source packages and reuse
attribution), then `0160` (immutable job/run source bindings), before deploying the
updated API and workers. These are additive; they do not infer historical run
metadata from a newer source. Their down migrations refuse to discard populated
source packages or retained bindings. Roll back exposure or application binaries
only with the schema compatibility gates satisfied; do not delete history to make
a down migration succeed.

An intact legacy source manifest can be promoted only after its retained archive
passes size and SHA-256 verification. A scope digest, database row or run summary
cannot reconstruct missing archive bytes or missing original upload attribution.
Restore the actual retained objects and metadata from a consistent backup when
available. Otherwise, if a completed predecessor still has uploaded-source scope
but its source metadata is missing, the Re-test UI disables **Use current source**
and permits **Upload new source** for a new child. This does not repair or relabel
older runs. If metadata exists but its archive is missing or corrupt, reuse and
scanning fail closed; upload another archive to a new Re-test rather than replacing
the old Assessment's source.
### Troubleshooting IaC scan finalization

The error `prepare redacted native observation: validation error: IaC config kind is unsupported`
can occur on pre-fix builds with native Snapshot capture enabled: the scanner emits
Dockerfile, Compose, GitHub Actions and ARM findings, but the original lineage
adapter recognized only Terraform, CloudFormation and Kubernetes. The failure can
mark a job failed at 100% after detection, before the scan result and Findings are
saved; an earlier immutable evidence-ledger append may already exist.

The fixed adapter retains all seven scanner families (Helm findings use Kubernetes).
The four newly accepted families have no approved resource-identity adapter yet,
so their observations are provisional and produce `needs_review` candidates, not
trusted cross-Snapshot matches. Repeated source fingerprints retain a review
candidate in each new Snapshot; same-Snapshot replay does not duplicate evidence
or reopen an explicitly resolved candidate. IaC coverage remains partial; a later
scan with no IaC finding does not prove Fixed. Unknown families and unsafe paths still fail
validation instead of silently dropping findings.

After upgrading the API and worker, start a new scan in the same non-completed
Engagement using available source input and valid scan authorization. Do not rewrite
the failed job or delete sealed evidence. No migration or new Re-test Engagement is
required for this fix. Disabling Snapshot capture is not a data-repair step.

Large closure reference cohorts (over 256 per kind) are represented as hashed
`*_set` references with source kind, exact count and earliest expiry. Report
generation resolves the complete ordered set at the manifest's as-of time. A
changed or missing source fails closed. High/Critical blocker cohorts use an
exact membership hash and require an explicit whole-cohort override reason;
incomplete verification remains a hard blocker. PostgreSQL history batches are
limited to 1000 Finding IDs and fail on excessive history rather than truncating it.

## Historical singleton-Cycle backfill

The production image includes `synapse-assessment-backfill`. It requires `SYNAPSE_DB_DSN`, does not execute Goose migrations, excludes hidden Project analysis-context Engagements, and never rewrites or deletes source rows.

Run a dry run first:

```bash
synapse-assessment-backfill \
  --tenants tenant-a \
  --dry-run \
  --batch-size 500
```

Run the write pass after reviewing the projected count:

```bash
synapse-assessment-backfill \
  --tenants tenant-a \
  --batch-size 500 \
  --timeout 2h
```

One process accepts at most four comma-separated tenants. Each tenant has one leased active run, a frozen source snapshot, a durable Assessment-ID checkpoint after every committed batch, and item outcomes in `assessment_cycle_backfill_items`. An expired lease resumes the existing run without creating duplicate Cycles. `--resume-after` supplies an initial checkpoint only for a single tenant.

The default batch is `500`; the enforced maximum is `2000`. Cancellation records a durable `cancelled` run. Stable item outcomes expose only reason codes, retryability, and bounded repair guidance; raw provider/database errors and tenant IDs are not Prometheus labels.

Metrics use bounded labels:

- `synapse_assessment_cycle_backfill_items_total{outcome="created|would_create|skipped|failed"}`
- `synapse_assessment_cycle_backfill_runs_total{state="completed|cancelled|failed"}`

Do not enable `SYNAPSE_ASSESSMENT_LIFECYCLE_READ_ENABLED` until backfill failures are repaired and the independent integrity verifier has completed for the same tenant set.

## Legacy Assessment Snapshot projection

After the singleton-Cycle backfill completes, run `synapse-assessment-snapshot-backfill`. The command requires `SYNAPSE_DB_DSN`, never runs during migration or API/worker startup, and appends immutable `legacy` Snapshots without changing the Assessment's default Snapshot pointer or rewriting scan runs.

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

The projection prefers verified sealed run manifests. Legacy run headers remain usable when lane provenance is unavailable, but the resulting Snapshot has no invented coverage dimensions. Every projected lane is forced to `legacy` provenance, so coverage remains `unknown`; the latest `scan_results` payload contributes only a SHA-256 source-evidence digest. A source change creates a new append-only projection, while an unchanged rerun records `already_projected`.

The command enforces one leased job per tenant, at most four tenants per process, batch `500` by default and `2000` maximum, durable checkpoints, bounded retries, cancellation, resume, tenant RLS, and stable redacted item records in `assessment_snapshot_backfill_items`.

- `synapse_assessment_snapshot_backfill_items_total{outcome="created|would_create|skipped|failed"}`
- `synapse_assessment_snapshot_backfill_runs_total{state="completed|cancelled|failed"}`

Creating a Re-test from a completed Cycle first requires `POST /api/v1/assessment-cycles/{cycleId}/reopen` with Review permission, `Idempotency-Key`, the current Cycle version in `If-Match`, and a non-empty audited `reason`.

## Finding Identity and Observation backfill

Run `synapse-finding-lineage-backfill` only after the Cycle and Snapshot backfills complete. It pages source Finding rows at the frozen cutoff by `(created_at, id COLLATE "C")`, resolves the selected Snapshot without changing its default pointer, and writes versioned Identities, immutable Observations, review Candidates, or explicit Skip records. It never copies workflow, SLA, disposition, assignee, raw evidence, or secret values. Mutable source rows updated after the cutoff are excluded.

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

The optional `--producers` filter accepts producer names and normalizes `iac`, `offensive`, and `cloud` to their stored Finding kinds. Omitting it processes every legacy Finding, including DAST/cloud rows that receive the stable `producer_matcher_unavailable` skip until their matchers ship. Missing or ambiguous Snapshot targets and missing semantic anchors create source-scoped provisional identities instead of fuzzy matches.

Every eligible source row records exactly one outcome in `finding_lineage_backfill_items`:

- `observation_created`
- `provisional_candidate_created`
- `skipped`

The run-level equality `processed = observation_created + provisional_candidate_created + skipped` is enforced in PostgreSQL. Idempotency binds the source Finding ID, matcher version, and Snapshot content hash. One leased run per tenant, at most four tenants per process, batch `500` default/`2000` maximum, checkpoint-per-batch, expired-lease resume, bounded retry, cancellation, forced RLS, and composite ownership FKs match the preceding lifecycle jobs.

- `synapse_finding_lineage_backfill_items_total{outcome="observation_created|provisional_candidate_created|skipped"}`
- `synapse_finding_lineage_backfill_runs_total{state="completed|cancelled|failed"}`

## Historical relationship review

After Cycle, Snapshot, and Finding lineage backfills complete, reviewers can open `/settings/relationships` or use the `/api/v1/assessment-relationship-candidates` endpoints to review possible predecessor/successor relationships between singleton Cycles. Generation is conservative: both Cycles must share the exact frozen boundary and must also have at least one explicit imported-reference hash, compatible trusted native manifest, or deterministic Finding overlap of at least two matches and `800` milli-score. Names, clients, dates, or a shared Asset alone never qualify.

Imported evidence is accepted only as a lowercase SHA-256 digest; raw imported metadata is rejected and never persisted. Candidate inputs are canonicalized into an `input_hash`, and identical generation returns the existing append-only artifact. A prior `reject` or `dismiss` therefore suppresses identical regeneration until a real input changes.

Decision requests require `PermReview`, `If-Match`, `Idempotency-Key`, and a bounded audit reason. Credential markers and URL userinfo are rejected. Candidates, decisions, and repair plans are tenant-owned under forced RLS, composite ownership foreign keys, append-only triggers, and guarded rollback in migration `0155`.

**Confirmation does not move, link, merge, or otherwise mutate any Assessment Cycle.** It only seals a deterministic repair-plan artifact with:

- `execution: blocked`
- `requires: separately_approved_move_merge_command`

There is no apply endpoint in this slice. Keep the plan blocked until a separately designed and approved move/merge command revalidates the frozen candidate inputs and current relationship versions.

Metrics use bounded labels and never include tenant, Cycle, candidate, or reviewer identifiers:

- `synapse_assessment_relationship_candidates_total{outcome="created|existing|failed",confidence="medium|high"}`
- `synapse_assessment_relationship_decisions_total{action="confirm|reject|dismiss",outcome="applied|replayed|failed"}`

## Integrity verification

Run the verifier after the write pass:

```bash
synapse-assessment-integrity \
  --tenants tenant-a \
  --dry-run \
  --batch-size 500
```

`--dry-run=false` is rejected. The verifier checks coverage, root/member shape, frozen boundaries, selected-head eligibility, Re-test allocation, predecessor integrity, graph acyclicity, and source/checkpoint reconciliation. A tenant-local source generation fences completion, so a concurrent Assessment, Cycle, or membership change forces the run to fail and restart instead of publishing a stale clean result. Findings are persisted under tenant RLS and emitted as JSON lines with stable reason/severity codes and deterministic repair plans. Any finding causes a non-zero exit and must be resolved before read cutover.

Verifier metrics also use bounded labels:

- `synapse_assessment_cycle_integrity_subjects_total{outcome="clean|finding"}`
- `synapse_assessment_cycle_integrity_runs_total{state="completed|cancelled|failed"}`

## Shadow Comparison backfill and deterministic repair

1. Start from current main, including #896: the response chain occupies `0138`–`0143` and ScanRun provenance occupies `0144`, and advisory alias indexing occupies `0145` (#921). Apply only assessment migrations `0146` through `0160`, including native comparison evidence, source packages and job/run source bindings. Preserve all released mainline migration names and contents; do not apply the superseded #883 renumbering.
2. Enable `SYNAPSE_ASSESSMENT_CYCLE_DUAL_WRITE_ENABLED` for an internal tenant allowlist.
3. Confirm new initial Assessments atomically create a Cycle and root member.
4. Run the Cycle and Snapshot backfills, then the Finding lineage backfill and integrity verifier.
5. Enable `SYNAPSE_ASSESSMENT_SNAPSHOT_ENABLED`.
6. Enable `SYNAPSE_ASSESSMENT_IDENTITY_COMPARISON_SHADOW_ENABLED` for a verified tenant allowlist and monitor the bounded Lineage metrics.
7. Enable `SYNAPSE_ASSESSMENT_LIFECYCLE_READ_ENABLED` for the verified tenant allowlist.
8. Enable `SYNAPSE_ASSESSMENT_LIFECYCLE_UI_DEFAULT_ENABLED` only for tenants already enabled for lifecycle reads.
9. After native Snapshot finalization is verified for the cohort, enable `SYNAPSE_ASSESSMENT_SNAPSHOT_COMPLETION_ENABLED` and add only those tenants to `SYNAPSE_ASSESSMENT_SNAPSHOT_COMPLETION_TENANTS`. Until this step, legacy Assessment completion remains available.

Enable Snapshot projection and the tenant-scoped shadow allowlist before queueing lifecycle Comparisons. The command refuses tenants outside `SYNAPSE_ASSESSMENT_IDENTITY_COMPARISON_SHADOW_TENANTS`, takes one PostgreSQL advisory lock per tenant, runs at most four tenant jobs per process, pages `500` Cycles by default (`2000` maximum), and records a resumable `(updated_at, cycle_id)` checkpoint after every batch. Lifecycle reads may be enabled only after the shadow gate passes; UI-default tenants must remain a subset of read-enabled tenants.

```bash
synapse-assessment-comparison-backfill \
  --tenants tenant-a \
  --dry-run \
  --batch-size 500

synapse-assessment-comparison-backfill \
  --tenants tenant-a \
  --repair-failed \
  --batch-size 500 \
  --timeout 2h
```

Re-run from the last logged checkpoint when interrupted:

```bash
synapse-assessment-comparison-backfill \
  --tenants tenant-a \
  --after-updated-at 2026-09-01T10:15:30Z \
  --after-cycle-id cycle-01J...
```

The runner queues only root-to-selected/final Snapshot pairs in `lifecycle` mode. Missing Snapshot defaults and singleton pairs are explicit skips; identical immutable generation inputs replay the existing Comparison. `--repair-failed` processes one deterministic oldest-first failed batch, regenerates the same Comparison ID, and reads it back to verify that the input hash and baseline/current Snapshot IDs did not change.

Legacy completion rollback: first remove the tenant from `SYNAPSE_ASSESSMENT_SNAPSHOT_COMPLETION_TENANTS`; preserve all stored artifacts.

Admission is fail-closed:

- warning at queued + generating backlog `>= 500`;
- no new queue admission once backlog reaches `1000`;
- abort when the oldest queued/generating Comparison exceeds `15m`;
- one active command per tenant through the advisory lock.

Worker metrics:

- `synapse_assessment_comparison_backlog{tenant_id,state="queued|generating|failed|dead_lettered"}`
- `synapse_assessment_comparison_oldest_active_age_seconds{tenant_id}`
- `synapse_assessment_comparison_generation_duration_seconds{tenant_id,mode,status,fingerprint_version,risk_model_version,item_count_band}`

The bounded `item_count_band="gte_100k"` series is the rollout measurement for the 100,000-item target. Use histogram quantiles to publish p50/p95/p99; do not infer a 100,000-item result from smaller bands.

## Canary, read cutover, and rollback

### Responsibility and stop authority

| Responsibility | Named owner |
| --- | --- |
| Release owner and phase ledger | Assessment lifecycle release owner |
| Integrity and Comparison repair | Data migration operator |
| API/UI SLO and alert review | Synapse API on-call |
| Security invariant approval | Security reviewer |
| Customer communication | Tenant success owner |

Any API on-call, data migration operator, or security reviewer has immediate stop authority. An abort does not require release-owner approval. Record the stop reason, affected tenant, last known-good phase, metric snapshot, and rollback result in the release change record and the active incident/operations channel.

### Phase ledger

For every tenant and phase, record start/end timestamps, the exact deployment revision, feature allowlists, dashboard snapshot, `synapse-assessment-rollout-gate` JSON input/output, approver, and communication link.

1. `internal_canary`: one internal/default tenant; shadow only.
2. `opt_in_canary`: one explicitly approved production tenant; shadow only.
3. `read_cutover`: enable tenant lifecycle reads only after the production `500/750ms` SLO holds for `30m` at target cardinality.
4. `ui_default`: enable tenant lifecycle UI only after read-cutover approval.
5. `rollback_drill`: disable reads/UI, retain source rows and immutable artifacts, verify legacy reads, then record operator sign-off.

The early-canary `750ms/1s` latency ceiling is an abort threshold only. It cannot approve phase 3.

### Automated gate

Export one bounded JSON snapshot from the persisted integrity/reconciliation records and Prometheus, then evaluate it before every phase transition:

```bash
synapse-assessment-rollout-gate \
  --phase read_cutover \
  --input tenant-a-read-cutover.json
```

The command exits non-zero and emits stable blocker codes when any invariant, mismatch, error-rate, latency, backlog, age, 100,000-item duration, dead-letter, approval, or rollback-preservation gate fails. `read_cutover` separately requires target cardinality and the production `500/750ms` SLO for `30m`; `ui_default` additionally requires recorded read-cutover approval.

### Dashboard queries

Adapt route labels to the deployed OpenAPI route names.

```promql
# API error rate, 15 minutes (abort > 0.01)
sum(rate(synapse_http_requests_total{status_class="5xx"}[15m]))
/
sum(rate(synapse_http_requests_total[15m]))

# Cycle-list p95
histogram_quantile(0.95,
  sum by (le) (rate(synapse_http_request_duration_seconds_bucket{route=~"GET /api/v1/assessment-cycles.*"}[15m])))

# Cycle-detail / Comparison-page p95
histogram_quantile(0.95,
  sum by (le,route) (rate(synapse_http_request_duration_seconds_bucket{route=~"GET /api/v1/assessment-cycles/.*|GET /api/v1/assessment-comparisons/.*"}[15m])))

# Per-tenant backlog and oldest active age
sum by (tenant_id) (synapse_assessment_comparison_backlog{state=~"queued|generating"})
synapse_assessment_comparison_oldest_active_age_seconds

# 100,000-item Comparison p50/p95/p99
histogram_quantile(0.50, sum by (le,tenant_id) (rate(synapse_assessment_comparison_generation_duration_seconds_bucket{item_count_band="gte_100k"}[30m])))
histogram_quantile(0.95, sum by (le,tenant_id) (rate(synapse_assessment_comparison_generation_duration_seconds_bucket{item_count_band="gte_100k"}[30m])))
histogram_quantile(0.99, sum by (le,tenant_id) (rate(synapse_assessment_comparison_generation_duration_seconds_bucket{item_count_band="gte_100k"}[30m])))

# Dead-letter growth without repair
delta(synapse_assessment_comparison_backlog{state="dead_lettered"}[10m])
```

Semantic mismatch rate comes from the immutable shadow reconciliation ledger: `semantic_mismatches / comparable_items`. It is authoritative only at `>= 1000` comparable items and must remain `<= 0.005`. Review-candidate rate is reported per producer and alerts above `10%` or twice the seven-day producer baseline, whichever is lower once a baseline exists.

### Rollback drill

1. Remove the tenant from `SYNAPSE_ASSESSMENT_LIFECYCLE_UI_DEFAULT_TENANTS` and deploy.
2. Remove the tenant from `SYNAPSE_ASSESSMENT_LIFECYCLE_READ_TENANTS` and deploy.
3. Keep Snapshot/shadow generation enabled until queued work drains or is deliberately stopped; do not delete source rows, Snapshots, Identities, Observations, Comparisons, closure manifests, or reports.
4. Verify `/api/v1/me` reports both lifecycle read/UI flags as false, lifecycle routes return `assessment_lifecycle_read_disabled`, the sidebar/panel remain hidden, and legacy Engagement reads still work.
5. Run `synapse-assessment-rollout-gate --phase rollback_drill` with preservation evidence and record operator/security approval.
