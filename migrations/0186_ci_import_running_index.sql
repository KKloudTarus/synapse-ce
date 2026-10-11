-- +goose Up
-- CI imports execute in external pipelines. Their short-lived importing state
-- must not reserve the engagement's asynchronous server-scan slot.
-- The index swap is transactional to preserve the server-scan uniqueness rule
-- across Up/Down, but rebuilding it blocks scan_jobs writes (and DROP may
-- block reads). Schedule this migration for a low-traffic window on large
-- scan histories; a concurrent replacement needs separate deployment fencing.
DROP INDEX scan_jobs_one_running_per_engagement;
CREATE UNIQUE INDEX scan_jobs_one_running_per_engagement
    ON scan_jobs (engagement_id)
    WHERE status = 'running' AND kind <> 'ci-import';

-- +goose Down
-- A rollback cannot restore the old index while concurrent CI imports remain
-- running. Mark those transient imports failed before restoring the old rule.
UPDATE scan_jobs
SET status = 'failed', stage = 'migration-rollback', progress = 100,
    error = 'CI import interrupted by running-index rollback', finished_at = now()
WHERE status = 'running' AND kind = 'ci-import';

DROP INDEX scan_jobs_one_running_per_engagement;
CREATE UNIQUE INDEX scan_jobs_one_running_per_engagement
    ON scan_jobs (engagement_id) WHERE status = 'running';
