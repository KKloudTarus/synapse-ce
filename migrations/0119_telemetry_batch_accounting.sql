-- +goose Up
-- Preserve the signed manifest's complete loss accounting in the immutable batch
-- commitment. Existing rows predate these fields and represent fully-kept batches.
ALTER TABLE telemetry_batch_commits
    DROP CONSTRAINT telemetry_batch_commits_event_count_check,
    ADD CONSTRAINT telemetry_batch_commits_event_count_check CHECK (event_count >= 0),
    ADD COLUMN observed_count INT,
    ADD COLUMN kept_count INT,
    ADD COLUMN sampled_out_count INT,
    ADD COLUMN truncated_count INT,
    ADD COLUMN dropped_count INT,
    ADD COLUMN sampling_policy_digest TEXT;

UPDATE telemetry_batch_commits
SET observed_count = event_count,
    kept_count = event_count,
    sampled_out_count = 0,
    truncated_count = 0,
    dropped_count = 0,
    sampling_policy_digest = 'legacy-pre-0119-fully-kept';

ALTER TABLE telemetry_batch_commits
    ALTER COLUMN observed_count SET NOT NULL,
    ALTER COLUMN kept_count SET NOT NULL,
    ALTER COLUMN sampled_out_count SET NOT NULL,
    ALTER COLUMN truncated_count SET NOT NULL,
    ALTER COLUMN dropped_count SET NOT NULL,
    ALTER COLUMN sampling_policy_digest SET NOT NULL,
    ADD CONSTRAINT telemetry_batch_commits_observed_count_nonnegative CHECK (observed_count >= 0),
    ADD CONSTRAINT telemetry_batch_commits_kept_count_nonnegative CHECK (kept_count >= 0),
    ADD CONSTRAINT telemetry_batch_commits_sampled_out_count_nonnegative CHECK (sampled_out_count >= 0),
    ADD CONSTRAINT telemetry_batch_commits_truncated_count_nonnegative CHECK (truncated_count >= 0),
    ADD CONSTRAINT telemetry_batch_commits_dropped_count_nonnegative CHECK (dropped_count >= 0),
    ADD CONSTRAINT telemetry_batch_commits_accounting_exact CHECK (
        observed_count = kept_count + sampled_out_count + dropped_count
    ),
    ADD CONSTRAINT telemetry_batch_commits_truncation_kept CHECK (truncated_count <= kept_count),
    ADD CONSTRAINT telemetry_batch_commits_event_count_kept CHECK (event_count = kept_count),
    ADD CONSTRAINT telemetry_batch_commits_sampling_policy_digest_nonempty CHECK (
        sampling_policy_digest <> ''
    );

-- +goose Down
ALTER TABLE telemetry_batch_commits
    DROP CONSTRAINT telemetry_batch_commits_sampling_policy_digest_nonempty,
    DROP CONSTRAINT telemetry_batch_commits_event_count_kept,
    DROP CONSTRAINT telemetry_batch_commits_truncation_kept,
    DROP CONSTRAINT telemetry_batch_commits_accounting_exact,
    DROP CONSTRAINT telemetry_batch_commits_dropped_count_nonnegative,
    DROP CONSTRAINT telemetry_batch_commits_truncated_count_nonnegative,
    DROP CONSTRAINT telemetry_batch_commits_sampled_out_count_nonnegative,
    DROP CONSTRAINT telemetry_batch_commits_kept_count_nonnegative,
    DROP CONSTRAINT telemetry_batch_commits_observed_count_nonnegative,
    DROP COLUMN sampling_policy_digest,
    DROP COLUMN dropped_count,
    DROP COLUMN truncated_count,
    DROP COLUMN sampled_out_count,
    DROP COLUMN kept_count,
    DROP COLUMN observed_count,
    DROP CONSTRAINT telemetry_batch_commits_event_count_check,
    ADD CONSTRAINT telemetry_batch_commits_event_count_check CHECK (event_count >= 1);
