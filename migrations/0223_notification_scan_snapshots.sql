-- +goose Up
-- The bounded terminal scan snapshot is written with scan_jobs.status. The
-- notification capture poller consumes this immutable row instead of current
-- finding state, which may already have changed by the time it runs.
ALTER TABLE scan_jobs
    ADD COLUMN notification_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT scan_jobs_notification_snapshot_object
        CHECK (jsonb_typeof(notification_snapshot) = 'object'),
    ADD CONSTRAINT scan_jobs_notification_snapshot_bounded
        CHECK (pg_column_size(notification_snapshot) <= 4194304);

CREATE INDEX idx_scan_jobs_succeeded_predecessor
    ON scan_jobs (engagement_id, kind, finished_at DESC NULLS LAST, id DESC)
    WHERE status = 'succeeded';

-- +goose Down
LOCK TABLE scan_jobs IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM scan_jobs WHERE notification_snapshot <> '{}'::jsonb) THEN
        RAISE EXCEPTION 'cannot remove recorded scan notification snapshots';
    END IF;
END
$$;
-- +goose StatementEnd
DROP INDEX IF EXISTS idx_scan_jobs_succeeded_predecessor;
ALTER TABLE scan_jobs
    DROP CONSTRAINT IF EXISTS scan_jobs_notification_snapshot_bounded,
    DROP CONSTRAINT IF EXISTS scan_jobs_notification_snapshot_object,
    DROP COLUMN IF EXISTS notification_snapshot;