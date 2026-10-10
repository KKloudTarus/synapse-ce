-- +goose Up
-- The original predecessor index cannot distinguish an immutable canonical
-- snapshot from an older job with no usable snapshot. MD5 is an accelerator
-- only: the lookup retains an exact target-key predicate in the query.
CREATE INDEX idx_scan_jobs_succeeded_notification_modern_predecessor
    ON scan_jobs (
        (engagement_id COLLATE "C"),
        (kind COLLATE "C"),
        md5(notification_snapshot->>'target_key'),
        finished_at DESC NULLS LAST,
        (id COLLATE "C") DESC
    )
    WHERE status = 'succeeded'
      AND notification_snapshot ? 'target_key'
      AND jsonb_typeof(notification_snapshot->'target_key') = 'string'
      AND notification_snapshot->>'target_key' <> '';

-- Empty, missing, and malformed target keys remain an explicit legacy
-- partition. Its keyset order exactly matches the repository's byte-order
-- predicate, so an unknown newer baseline cannot be skipped for an older one.
CREATE INDEX idx_scan_jobs_succeeded_notification_legacy_predecessor
    ON scan_jobs (
        (engagement_id COLLATE "C"),
        (kind COLLATE "C"),
        finished_at DESC NULLS LAST,
        (id COLLATE "C") DESC
    )
    WHERE status = 'succeeded'
      AND (
          NOT (notification_snapshot ? 'target_key')
          OR jsonb_typeof(notification_snapshot->'target_key') <> 'string'
          OR notification_snapshot->>'target_key' = ''
      );

DROP INDEX IF EXISTS idx_scan_jobs_succeeded_predecessor;

-- +goose Down
CREATE INDEX idx_scan_jobs_succeeded_predecessor
    ON scan_jobs (engagement_id, kind, finished_at DESC NULLS LAST, id DESC)
    WHERE status = 'succeeded';

DROP INDEX IF EXISTS idx_scan_jobs_succeeded_notification_legacy_predecessor;
DROP INDEX IF EXISTS idx_scan_jobs_succeeded_notification_modern_predecessor;
