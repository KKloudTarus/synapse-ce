-- +goose Up
-- A9b.2 (#731): resumable, read-only Assessment Cycle integrity verification and repair plans.

CREATE TABLE assessment_cycle_integrity_runs (
    tenant_id                TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id                       TEXT NOT NULL,
    batch_size               INTEGER NOT NULL,
    snapshot_at              TIMESTAMPTZ NOT NULL,
    checkpoint_assessment_id TEXT NOT NULL DEFAULT '',
    state                    TEXT NOT NULL,
    lease_owner              TEXT NOT NULL DEFAULT '',
    lease_expires_at         TIMESTAMPTZ NULL,
    scanned_count            INTEGER NOT NULL DEFAULT 0,
    clean_count              INTEGER NOT NULL DEFAULT 0,
    finding_count            INTEGER NOT NULL DEFAULT 0,
    created_by               TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL,
    completed_at             TIMESTAMPTZ NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT assessment_cycle_integrity_runs_batch_check CHECK (batch_size BETWEEN 1 AND 2000),
    CONSTRAINT assessment_cycle_integrity_runs_checkpoint_check CHECK (octet_length(checkpoint_assessment_id) <= 512),
    CONSTRAINT assessment_cycle_integrity_runs_state_check CHECK (state IN ('running', 'completed', 'cancelled', 'failed')),
    CONSTRAINT assessment_cycle_integrity_runs_lease_check CHECK (
        (state = 'running' AND lease_owner = btrim(lease_owner) AND length(lease_owner) BETWEEN 1 AND 256 AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
        (state <> 'running' AND lease_owner = '' AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    ),
    CONSTRAINT assessment_cycle_integrity_runs_counts_check CHECK (
        scanned_count >= 0 AND clean_count >= 0 AND finding_count >= 0 AND clean_count <= scanned_count AND
        (finding_count > 0 OR clean_count = scanned_count)
    ),
    CONSTRAINT assessment_cycle_integrity_runs_actor_check CHECK (created_by = btrim(created_by) AND length(created_by) BETWEEN 1 AND 256),
    CONSTRAINT assessment_cycle_integrity_runs_time_check CHECK (updated_at >= created_at AND snapshot_at <= created_at AND (completed_at IS NULL OR completed_at >= created_at))
);

CREATE UNIQUE INDEX uq_assessment_cycle_integrity_runs_active
    ON assessment_cycle_integrity_runs (tenant_id)
    WHERE state = 'running';
CREATE INDEX idx_assessment_cycle_integrity_runs_history
    ON assessment_cycle_integrity_runs (tenant_id, created_at DESC, id DESC);

CREATE TABLE assessment_cycle_integrity_subjects (
    tenant_id      TEXT NOT NULL,
    run_id         TEXT NOT NULL,
    assessment_id  TEXT NOT NULL,
    clean           BOOLEAN NOT NULL,
    finding_count   INTEGER NOT NULL,
    processed_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, run_id, assessment_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES assessment_cycle_integrity_runs(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, assessment_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT assessment_cycle_integrity_subjects_counts_check CHECK (finding_count >= 0 AND clean = (finding_count = 0))
);

CREATE TABLE assessment_cycle_integrity_findings (
    tenant_id       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    occurrence_id   TEXT NOT NULL,
    assessment_id   TEXT NOT NULL,
    cycle_id        TEXT NULL,
    member_id       TEXT NULL,
    reason_code     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    repair_plan     JSONB NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, run_id, occurrence_id),
    FOREIGN KEY (tenant_id, run_id, assessment_id) REFERENCES assessment_cycle_integrity_subjects(tenant_id, run_id, assessment_id) ON DELETE RESTRICT,
    CONSTRAINT assessment_cycle_integrity_findings_occurrence_check CHECK (occurrence_id ~ '^[0-9a-f]{32}$'),
    CONSTRAINT assessment_cycle_integrity_findings_member_check CHECK ((cycle_id IS NULL AND member_id IS NULL) OR cycle_id IS NOT NULL),
    CONSTRAINT assessment_cycle_integrity_findings_reason_check CHECK (reason_code ~ '^[a-z0-9_]{1,64}$'),
    CONSTRAINT assessment_cycle_integrity_findings_severity_check CHECK (severity IN ('medium', 'high', 'critical')),
    CONSTRAINT assessment_cycle_integrity_findings_repair_check CHECK (jsonb_typeof(repair_plan) = 'object' AND octet_length(repair_plan::text) <= 8192)
);

CREATE INDEX idx_assessment_cycle_integrity_findings_reason
    ON assessment_cycle_integrity_findings (tenant_id, run_id, severity, reason_code, occurrence_id);

CALL synapse_enable_tenant_rls('assessment_cycle_integrity_runs');
CALL synapse_enable_tenant_rls('assessment_cycle_integrity_subjects');
CALL synapse_enable_tenant_rls('assessment_cycle_integrity_findings');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM assessment_cycle_integrity_findings LIMIT 1) OR
       EXISTS (SELECT 1 FROM assessment_cycle_integrity_subjects LIMIT 1) OR
       EXISTS (SELECT 1 FROM assessment_cycle_integrity_runs LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back assessment cycle integrity state while verification history exists';
    END IF;
END;
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS assessment_cycle_integrity_findings;
DROP TABLE IF EXISTS assessment_cycle_integrity_subjects;
DROP TABLE IF EXISTS assessment_cycle_integrity_runs;
