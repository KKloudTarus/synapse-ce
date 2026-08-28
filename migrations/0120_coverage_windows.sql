-- +goose Up
-- Deterministic materializations of immutable sensor/accounting/gap facts. New
-- late-arriving facts append a new revision; accepted revisions cannot be edited.
CREATE TABLE coverage_windows (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    revision        TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    host_id         TEXT NOT NULL,
    since_at        TIMESTAMPTZ NOT NULL,
    until_at        TIMESTAMPTZ NOT NULL CHECK (until_at > since_at),
    input_digest    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    states          JSONB NOT NULL,
    sampled_count   INT NOT NULL CHECK (sampled_count >= 0),
    truncated_count INT NOT NULL CHECK (truncated_count >= 0),
    dropped_count   INT NOT NULL CHECK (dropped_count >= 0),
    gap_count       INT NOT NULL CHECK (gap_count >= 0),
    batch_count     INT NOT NULL CHECK (batch_count >= 0),
    coverage_vector JSONB NOT NULL,
    PRIMARY KEY (tenant_id, revision),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id),
    CONSTRAINT coverage_windows_revision_sha256 CHECK (revision ~ '^[0-9a-f]{64}$'),
    CONSTRAINT coverage_windows_input_digest_sha256 CHECK (input_digest ~ '^[0-9a-f]{64}$')
);
CREATE INDEX idx_coverage_windows_asset_time
    ON coverage_windows (tenant_id, asset_id, host_id, since_at DESC, until_at DESC, revision DESC);
CREATE INDEX idx_coverage_windows_agent_time
    ON coverage_windows (tenant_id, agent_id, since_at DESC, until_at DESC, revision DESC);
CALL synapse_enable_tenant_rls('coverage_windows');

CREATE TRIGGER coverage_windows_append_only
    BEFORE UPDATE OR DELETE ON coverage_windows
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER coverage_windows_no_truncate
    BEFORE TRUNCATE ON coverage_windows
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- Signed telemetry commitments are immutable source facts too. Prior migrations
-- did not install mutation guards because the table was initially a transport
-- implementation detail; coverage revisions now consume it as durable evidence.
-- Only REWRITES are forbidden: the commitment is retention-bound transport data,
-- not chained evidence, so pruning a batch must remain possible.
CREATE TRIGGER telemetry_batch_commits_immutable_commitment
    BEFORE UPDATE ON telemetry_batch_commits
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER telemetry_batch_commits_no_truncate
    BEFORE TRUNCATE ON telemetry_batch_commits
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
-- Coverage revisions and signed batch commitments are evidence of visibility
-- limits. Refuse rollback rather than silently deleting accepted facts.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM coverage_windows) THEN
        RAISE EXCEPTION 'cannot roll back 0120: coverage-window revisions exist';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS telemetry_batch_commits_no_truncate ON telemetry_batch_commits;
DROP TRIGGER IF EXISTS telemetry_batch_commits_immutable_commitment ON telemetry_batch_commits;
DROP TRIGGER IF EXISTS coverage_windows_no_truncate ON coverage_windows;
DROP TRIGGER IF EXISTS coverage_windows_append_only ON coverage_windows;
DROP TABLE coverage_windows;
