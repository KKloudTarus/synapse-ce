-- +goose Up
-- Keep periodic recovery discovery independent of terminal authenticated-run history.
CREATE INDEX idx_dast_runs_recovery ON dast_runs (tenant_id, scan_job_id)
    WHERE kind = 'authenticated_scan' AND status IN ('queued', 'running');

-- +goose Down
DROP INDEX idx_dast_runs_recovery;
