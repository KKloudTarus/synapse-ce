-- +goose Up
-- A9c (#718): resumable, append-only legacy Assessment Snapshot projection state.

ALTER TABLE assessment_snapshots
    ADD CONSTRAINT assessment_snapshots_tenant_assessment_id_unique UNIQUE (tenant_id, assessment_id, id);

CREATE TABLE assessment_snapshot_backfill_runs (
    tenant_id               TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id                      TEXT NOT NULL,
    schema_version          INTEGER NOT NULL,
    dry_run                 BOOLEAN NOT NULL,
    batch_size              INTEGER NOT NULL,
    snapshot_at             TIMESTAMPTZ NOT NULL,
    checkpoint_assessment_id TEXT NOT NULL DEFAULT '',
    state                   TEXT NOT NULL,
    lease_owner             TEXT NOT NULL DEFAULT '',
    lease_expires_at        TIMESTAMPTZ NULL,
    processed_count         INTEGER NOT NULL DEFAULT 0,
    created_count           INTEGER NOT NULL DEFAULT 0,
    would_create_count      INTEGER NOT NULL DEFAULT 0,
    skipped_count           INTEGER NOT NULL DEFAULT 0,
    failed_count            INTEGER NOT NULL DEFAULT 0,
    created_by              TEXT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL,
    updated_at              TIMESTAMPTZ NOT NULL,
    completed_at            TIMESTAMPTZ NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT assessment_snapshot_backfill_runs_schema_check CHECK (schema_version > 0),
    CONSTRAINT assessment_snapshot_backfill_runs_batch_check CHECK (batch_size BETWEEN 1 AND 2000),
    CONSTRAINT assessment_snapshot_backfill_runs_checkpoint_check CHECK (octet_length(checkpoint_assessment_id) <= 512),
    CONSTRAINT assessment_snapshot_backfill_runs_state_check CHECK (state IN ('running', 'completed', 'cancelled', 'failed')),
    CONSTRAINT assessment_snapshot_backfill_runs_lease_check CHECK (
        (state = 'running' AND lease_owner = btrim(lease_owner) AND length(lease_owner) BETWEEN 1 AND 256 AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
        (state <> 'running' AND lease_owner = '' AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    ),
    CONSTRAINT assessment_snapshot_backfill_runs_counts_check CHECK (
        processed_count >= 0 AND created_count >= 0 AND would_create_count >= 0 AND skipped_count >= 0 AND failed_count >= 0 AND
        processed_count = created_count + would_create_count + skipped_count + failed_count
    ),
    CONSTRAINT assessment_snapshot_backfill_runs_actor_check CHECK (created_by = btrim(created_by) AND length(created_by) BETWEEN 1 AND 256),
    CONSTRAINT assessment_snapshot_backfill_runs_time_check CHECK (updated_at >= created_at AND snapshot_at <= created_at AND (completed_at IS NULL OR completed_at >= created_at))
);

CREATE UNIQUE INDEX uq_assessment_snapshot_backfill_runs_active
    ON assessment_snapshot_backfill_runs (tenant_id)
    WHERE state = 'running';
CREATE INDEX idx_assessment_snapshot_backfill_runs_history
    ON assessment_snapshot_backfill_runs (tenant_id, created_at DESC, id DESC);

CREATE TABLE assessment_snapshot_backfill_items (
    tenant_id       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    assessment_id   TEXT NOT NULL,
    schema_version  INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL,
    source_hash     TEXT NOT NULL,
    snapshot_id     TEXT NULL,
    outcome         TEXT NOT NULL,
    reason_code     TEXT NOT NULL,
    retryable       BOOLEAN NOT NULL DEFAULT FALSE,
    repair_guidance TEXT NOT NULL DEFAULT '',
    processed_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, run_id, assessment_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES assessment_snapshot_backfill_runs(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, assessment_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, assessment_id, snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, assessment_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, run_id, idempotency_key),
    CONSTRAINT assessment_snapshot_backfill_items_schema_check CHECK (schema_version > 0),
    CONSTRAINT assessment_snapshot_backfill_items_key_check CHECK (idempotency_key = btrim(idempotency_key) AND length(idempotency_key) BETWEEN 1 AND 128),
    CONSTRAINT assessment_snapshot_backfill_items_source_hash_check CHECK (source_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT assessment_snapshot_backfill_items_outcome_check CHECK (outcome IN ('created', 'would_create', 'skipped', 'failed')),
    CONSTRAINT assessment_snapshot_backfill_items_reason_check CHECK (reason_code ~ '^[a-z0-9_]{1,64}$'),
    CONSTRAINT assessment_snapshot_backfill_items_guidance_check CHECK (octet_length(repair_guidance) <= 1024),
    CONSTRAINT assessment_snapshot_backfill_items_snapshot_check CHECK (
        (outcome = 'created' AND snapshot_id IS NOT NULL) OR
        (outcome IN ('would_create', 'failed') AND snapshot_id IS NULL) OR
        outcome = 'skipped'
    )
);

CREATE INDEX idx_assessment_snapshot_backfill_items_outcome
    ON assessment_snapshot_backfill_items (tenant_id, run_id, outcome, assessment_id);

CALL synapse_enable_tenant_rls('assessment_snapshot_backfill_runs');
CALL synapse_enable_tenant_rls('assessment_snapshot_backfill_items');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM assessment_snapshot_backfill_items LIMIT 1) OR
       EXISTS (SELECT 1 FROM assessment_snapshot_backfill_runs LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back assessment snapshot backfill state while run history exists';
    END IF;
END;
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS assessment_snapshot_backfill_items;
DROP TABLE IF EXISTS assessment_snapshot_backfill_runs;
ALTER TABLE assessment_snapshots DROP CONSTRAINT IF EXISTS assessment_snapshots_tenant_assessment_id_unique;
