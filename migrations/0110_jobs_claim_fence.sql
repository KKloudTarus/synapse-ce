-- +goose Up
-- claim_fence is a monotonically increasing generation assigned by each successful claim.
-- A worker may mutate a job only while its fence matches this row, preventing an expired
-- lease holder from publishing terminal state after another worker reclaimed the job.
ALTER TABLE jobs ADD COLUMN claim_fence BIGINT NOT NULL DEFAULT 0;
COMMENT ON COLUMN jobs.claim_fence IS 'Monotonically increasing claim generation; fenced mutations require the current claimed generation.';

-- +goose Down
ALTER TABLE jobs DROP COLUMN IF EXISTS claim_fence;
