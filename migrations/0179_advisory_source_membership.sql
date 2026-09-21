-- +goose NO TRANSACTION
-- +goose Up
-- Keep source-membership retirement queryable without repeatedly filtering JSON payloads.
-- This is a metadata-only addition for prior releases: source-local absence observations
-- are introduced with this writer, so no historical JSON backfill is needed.
SET lock_timeout = '5s';
ALTER TABLE advisory_observations
    ADD COLUMN IF NOT EXISTS absence_retirement BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS advisory_observations_current_active_source_record
    ON advisory_observations(source_id, record_id)
    WHERE is_current AND NOT absence_retirement;

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS advisory_observations_current_active_source_record;
ALTER TABLE advisory_observations DROP COLUMN IF EXISTS absence_retirement;
