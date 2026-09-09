-- +goose Up
CREATE TABLE response_target_evidence_receipts (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    receipt_id TEXT NOT NULL,
    attempt_key TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    engagement_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    verification_challenge TEXT NOT NULL CHECK (verification_challenge ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL,
    receipt JSONB NOT NULL,
    PRIMARY KEY (tenant_id, receipt_id),
    UNIQUE (tenant_id, attempt_key),
    UNIQUE (tenant_id, digest)
);
CALL synapse_enable_tenant_rls('response_target_evidence_receipts');
CREATE INDEX idx_response_target_evidence_receipts_action ON response_target_evidence_receipts (tenant_id, action_id, recorded_at);
CREATE INDEX idx_response_target_evidence_receipts_engagement ON response_target_evidence_receipts (tenant_id, engagement_id, recorded_at);
CREATE TRIGGER response_target_evidence_receipts_append_only BEFORE UPDATE OR DELETE ON response_target_evidence_receipts FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER response_target_evidence_receipts_no_truncate BEFORE TRUNCATE ON response_target_evidence_receipts FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS response_target_evidence_receipts_no_truncate ON response_target_evidence_receipts;
DROP TRIGGER IF EXISTS response_target_evidence_receipts_append_only ON response_target_evidence_receipts;
DROP TABLE response_target_evidence_receipts;
