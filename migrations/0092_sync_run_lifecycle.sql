-- +goose Up
-- Complete the sync-run lifecycle without changing the global/tenant boundary:
-- runs and provider history are global; only the durable worker job is tenant-scoped.
ALTER TABLE vulnerability_sync_runs
    DROP CONSTRAINT vulnerability_sync_runs_state_check;
ALTER TABLE vulnerability_sync_runs
    ADD CONSTRAINT vulnerability_sync_runs_state_check
    CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'partial', 'superseded'));

ALTER TABLE vulnerability_sync_runs
    ADD COLUMN source_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(source_snapshot) = 'object'),
    ADD COLUMN processed_count BIGINT NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
    ADD COLUMN inserted_count BIGINT NOT NULL DEFAULT 0 CHECK (inserted_count >= 0),
    ADD COLUMN updated_count BIGINT NOT NULL DEFAULT 0 CHECK (updated_count >= 0),
    ADD COLUMN unchanged_count BIGINT NOT NULL DEFAULT 0 CHECK (unchanged_count >= 0),
    ADD COLUMN quarantined_count BIGINT NOT NULL DEFAULT 0 CHECK (quarantined_count >= 0),
    ADD COLUMN last_error TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX vulnerability_sync_runs_durable_job_key
    ON vulnerability_sync_runs(durable_job_id) WHERE durable_job_id IS NOT NULL;
CREATE INDEX idx_vulnerability_sync_runs_stale
    ON vulnerability_sync_runs(updated_at, source_id)
    WHERE state IN ('queued', 'running');

-- +goose Down
DROP INDEX IF EXISTS idx_vulnerability_sync_runs_stale;
DROP INDEX IF EXISTS vulnerability_sync_runs_durable_job_key;
ALTER TABLE vulnerability_sync_runs
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS quarantined_count,
    DROP COLUMN IF EXISTS unchanged_count,
    DROP COLUMN IF EXISTS updated_count,
    DROP COLUMN IF EXISTS inserted_count,
    DROP COLUMN IF EXISTS processed_count,
    DROP COLUMN IF EXISTS source_snapshot;
ALTER TABLE vulnerability_sync_runs
    DROP CONSTRAINT vulnerability_sync_runs_state_check;
ALTER TABLE vulnerability_sync_runs
    ADD CONSTRAINT vulnerability_sync_runs_state_check
    CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'partial'));
