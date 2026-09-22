-- +goose Up
-- Preserve a complete authoritative source snapshot and its provider checkpoint with
-- the observation/revision transaction so reconciliation can resume without refetching.
CREATE TABLE vulnerability_source_snapshot_publications (
    sync_run_id     TEXT PRIMARY KEY REFERENCES vulnerability_sync_runs(id) ON DELETE RESTRICT,
    source_id       TEXT NOT NULL REFERENCES vulnerability_sources(id),
    adapter_type    TEXT NOT NULL,
    next_checkpoint JSONB NOT NULL CHECK (jsonb_typeof(next_checkpoint) = 'object'),
    result_count    INTEGER NOT NULL CHECK (result_count > 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vulnerability_source_snapshot_results (
    sync_run_id      TEXT NOT NULL REFERENCES vulnerability_source_snapshot_publications(sync_run_id) ON DELETE CASCADE,
    result_index     INTEGER NOT NULL CHECK (result_index >= 0),
    advisory_id      TEXT NOT NULL,
    revision         BIGINT NOT NULL CHECK (revision > 0),
    content_hash     TEXT NOT NULL,
    changed_fields   JSONB NOT NULL CHECK (jsonb_typeof(changed_fields) = 'array'),
    created_revision BOOLEAN NOT NULL,
    PRIMARY KEY (sync_run_id, result_index),
    FOREIGN KEY (advisory_id, revision) REFERENCES advisory_revisions(advisory_id, revision) ON DELETE RESTRICT
);

CREATE INDEX idx_vulnerability_source_snapshot_publications_source
    ON vulnerability_source_snapshot_publications(source_id, created_at DESC);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_guard_authoritative_snapshot_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'authoritative source snapshot publications are immutable';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER vulnerability_source_snapshot_publications_immutable
    BEFORE UPDATE OR DELETE ON vulnerability_source_snapshot_publications
    FOR EACH ROW EXECUTE FUNCTION synapse_guard_authoritative_snapshot_mutation();

CREATE TRIGGER vulnerability_source_snapshot_results_immutable
    BEFORE UPDATE OR DELETE ON vulnerability_source_snapshot_results
    FOR EACH ROW EXECUTE FUNCTION synapse_guard_authoritative_snapshot_mutation();

CREATE TRIGGER vulnerability_source_snapshot_publications_no_truncate
    BEFORE TRUNCATE ON vulnerability_source_snapshot_publications
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_guard_authoritative_snapshot_mutation();

CREATE TRIGGER vulnerability_source_snapshot_results_no_truncate
    BEFORE TRUNCATE ON vulnerability_source_snapshot_results
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_guard_authoritative_snapshot_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS vulnerability_source_snapshot_results_no_truncate ON vulnerability_source_snapshot_results;
DROP TRIGGER IF EXISTS vulnerability_source_snapshot_publications_no_truncate ON vulnerability_source_snapshot_publications;
DROP TRIGGER IF EXISTS vulnerability_source_snapshot_results_immutable ON vulnerability_source_snapshot_results;
DROP TRIGGER IF EXISTS vulnerability_source_snapshot_publications_immutable ON vulnerability_source_snapshot_publications;
DROP FUNCTION IF EXISTS synapse_guard_authoritative_snapshot_mutation();
DROP TABLE IF EXISTS vulnerability_source_snapshot_results;
DROP TABLE IF EXISTS vulnerability_source_snapshot_publications;
