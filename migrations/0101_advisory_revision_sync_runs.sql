-- +goose Up
CREATE TABLE advisory_revision_sync_runs (
    advisory_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    sync_run_id TEXT NOT NULL REFERENCES vulnerability_sync_runs(id),
    PRIMARY KEY (advisory_id, revision, sync_run_id),
    FOREIGN KEY (advisory_id, revision) REFERENCES advisory_revisions(advisory_id, revision) ON DELETE CASCADE
);

CREATE INDEX idx_advisory_revision_sync_runs_run
    ON advisory_revision_sync_runs(sync_run_id, advisory_id, revision);

-- +goose Down
DROP TABLE IF EXISTS advisory_revision_sync_runs;
