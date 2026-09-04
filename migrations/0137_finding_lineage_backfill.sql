-- +goose Up
-- A9d (#719): resumable Finding Identity and Observation backfill state.

ALTER TABLE findings
    ADD CONSTRAINT findings_tenant_id_id_unique UNIQUE (tenant_id, id);

CREATE TABLE finding_lineage_backfill_runs (
    tenant_id                   TEXT NOT NULL,
    id                          TEXT NOT NULL,
    schema_version              INTEGER NOT NULL,
    dry_run                     BOOLEAN NOT NULL,
    batch_size                  INTEGER NOT NULL,
    producer_filters            TEXT[] NOT NULL DEFAULT '{}',
    snapshot_at                 TIMESTAMPTZ NOT NULL,
    checkpoint_finding_id       TEXT NOT NULL DEFAULT '',
    state                       TEXT NOT NULL,
    lease_owner                 TEXT NOT NULL DEFAULT '',
    lease_token                 TEXT NOT NULL DEFAULT '',
    lease_expires_at            TIMESTAMPTZ,
    processed_count             INTEGER NOT NULL DEFAULT 0,
    observation_created_count   INTEGER NOT NULL DEFAULT 0,
    provisional_candidate_count INTEGER NOT NULL DEFAULT 0,
    skipped_count               INTEGER NOT NULL DEFAULT 0,
    created_by                  TEXT NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL,
    completed_at                TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT,
    CONSTRAINT finding_lineage_backfill_runs_schema_check CHECK (schema_version > 0),
    CONSTRAINT finding_lineage_backfill_runs_batch_check CHECK (batch_size BETWEEN 1 AND 2000),
    CONSTRAINT finding_lineage_backfill_runs_filter_check CHECK (
        producer_filters <@ ARRAY['sca','recon','exploitation','manual','sast','secret','misconfig','cloud_posture','dast','threat','hypothesis','quality','reliability']::TEXT[]
    ),
    CONSTRAINT finding_lineage_backfill_runs_checkpoint_check CHECK (octet_length(checkpoint_finding_id) <= 512),
    CONSTRAINT finding_lineage_backfill_runs_state_check CHECK (state IN ('running','completed','cancelled','failed')),
    CONSTRAINT finding_lineage_backfill_runs_lease_check CHECK (
        (state = 'running' AND lease_owner = btrim(lease_owner) AND length(lease_owner) BETWEEN 1 AND 256 AND length(lease_token) BETWEEN 1 AND 512 AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
        (state <> 'running' AND lease_owner = '' AND lease_token = '' AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    ),
    CONSTRAINT finding_lineage_backfill_runs_counts_check CHECK (
        processed_count >= 0 AND observation_created_count >= 0 AND provisional_candidate_count >= 0 AND skipped_count >= 0 AND
        processed_count = observation_created_count + provisional_candidate_count + skipped_count
    ),
    CONSTRAINT finding_lineage_backfill_runs_actor_check CHECK (created_by = btrim(created_by) AND length(created_by) BETWEEN 1 AND 256),
    CONSTRAINT finding_lineage_backfill_runs_time_check CHECK (updated_at >= created_at AND snapshot_at <= created_at AND (completed_at IS NULL OR completed_at >= created_at))
);

CREATE UNIQUE INDEX uq_finding_lineage_backfill_runs_active
    ON finding_lineage_backfill_runs (tenant_id) WHERE state = 'running';
CREATE INDEX idx_finding_lineage_backfill_runs_history
    ON finding_lineage_backfill_runs (tenant_id, created_at DESC, id DESC);

CREATE TABLE finding_lineage_backfill_items (
    tenant_id        TEXT NOT NULL,
    run_id           TEXT NOT NULL,
    assessment_id    TEXT NOT NULL,
    cycle_id         TEXT,
    snapshot_id      TEXT,
    source_finding_id TEXT NOT NULL,
    schema_version   INTEGER NOT NULL,
    matcher_version  INTEGER NOT NULL,
    idempotency_key  TEXT NOT NULL,
    source_hash      TEXT NOT NULL,
    outcome          TEXT NOT NULL,
    reason_code      TEXT NOT NULL,
    processed_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, run_id, source_finding_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES finding_lineage_backfill_runs(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, assessment_id, source_finding_id) REFERENCES findings(tenant_id, engagement_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, assessment_id) REFERENCES assessment_cycle_members(tenant_id, cycle_id, assessment_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, assessment_id, snapshot_id) REFERENCES assessment_snapshots(tenant_id, assessment_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, run_id, idempotency_key),
    CONSTRAINT finding_lineage_backfill_items_schema_check CHECK (schema_version > 0 AND matcher_version > 0),
    CONSTRAINT finding_lineage_backfill_items_key_check CHECK (idempotency_key = btrim(idempotency_key) AND length(idempotency_key) BETWEEN 1 AND 128),
    CONSTRAINT finding_lineage_backfill_items_source_hash_check CHECK (source_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT finding_lineage_backfill_items_outcome_check CHECK (outcome IN ('observation_created','provisional_candidate_created','skipped')),
    CONSTRAINT finding_lineage_backfill_items_reason_check CHECK (reason_code ~ '^[a-z0-9_]{1,64}$'),
    CONSTRAINT finding_lineage_backfill_items_reference_check CHECK (
        (outcome = 'skipped') OR (cycle_id IS NOT NULL AND snapshot_id IS NOT NULL)
    )
);

CREATE INDEX idx_finding_lineage_backfill_items_outcome
    ON finding_lineage_backfill_items (tenant_id, run_id, outcome, source_finding_id);

CALL synapse_enable_tenant_rls('finding_lineage_backfill_runs');
CALL synapse_enable_tenant_rls('finding_lineage_backfill_items');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM finding_lineage_backfill_items LIMIT 1) OR
       EXISTS (SELECT 1 FROM finding_lineage_backfill_runs LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back finding lineage backfill state while run history exists';
    END IF;
END;
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS finding_lineage_backfill_items;
DROP TABLE IF EXISTS finding_lineage_backfill_runs;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_tenant_id_id_unique;
