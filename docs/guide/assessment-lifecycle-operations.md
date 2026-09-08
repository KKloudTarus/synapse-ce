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
- **Uploaded source:** choose a new ZIP/TAR archive when copying uploaded-source
  scope (non-empty, maximum 512 MiB). The predecessor archive is not reused. A
  changed archive retains its own content digest and the Cycle source namespace.
- **Authorization:** enter new start/end bounds and allowed tool classes, or save
  a non-executable draft. Planned date is planning only. Previous authorization,
  RoE and scanner profiles are never inherited implicitly.
- **Compare:** choose two finalized Snapshots. Ordered snapshots/ancestry permit
  lifecycle classification; reverse or sibling pairs require neutral diff. Missing,
  partial, unknown or changed detection coverage is never evidence of Fixed.
  Finding-level verification remains a separate workflow.
- **Close/reopen:** reviewers use signed, expiring preview/commit commands. Closure
  freezes the root-to-selected-head path and generates a JSON report. Reopen
  supersedes the old manifest; it does not rewrite or remove its report/history.

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

Decision requests require `PermReview`, `If-Match`, `Idempotency-Key`, and a bounded audit reason. Credential markers and URL userinfo are rejected. Candidates, decisions, and repair plans are tenant-owned under forced RLS, composite ownership foreign keys, append-only triggers, and guarded rollback in migration `0148`.

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

1. Apply the additive migration chain `0138` through `0151` (ScanRun provenance through immutable native comparison evidence). Released migrations `0001` through `0137` are unchanged.
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
