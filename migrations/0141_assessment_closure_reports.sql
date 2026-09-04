-- +goose Up
-- A10b (#722): immutable deterministic report artifacts keyed by closure manifest + renderer contract.

CREATE TABLE assessment_cycle_closure_reports (
    tenant_id                  TEXT NOT NULL,
    cycle_id                   TEXT NOT NULL,
    manifest_id                TEXT NOT NULL,
    renderer_contract_version  TEXT NOT NULL,
    content_hash               TEXT NOT NULL,
    content                    BYTEA NOT NULL,
    generated_at               TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, cycle_id, manifest_id, renderer_contract_version),
    FOREIGN KEY (tenant_id, cycle_id, manifest_id)
        REFERENCES assessment_cycle_closure_manifests(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    CONSTRAINT assessment_cycle_closure_report_renderer_check CHECK (
        renderer_contract_version = btrim(renderer_contract_version) AND length(renderer_contract_version) BETWEEN 1 AND 128
    ),
    CONSTRAINT assessment_cycle_closure_report_hash_check CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT assessment_cycle_closure_report_content_check CHECK (octet_length(content) BETWEEN 2 AND 16777216)
);

CREATE INDEX idx_assessment_cycle_closure_report_hash
    ON assessment_cycle_closure_reports (tenant_id, content_hash);

CREATE TRIGGER assessment_cycle_closure_reports_immutable
BEFORE UPDATE OR DELETE ON assessment_cycle_closure_reports
FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER assessment_cycle_closure_reports_no_truncate
BEFORE TRUNCATE ON assessment_cycle_closure_reports
FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

CALL synapse_enable_tenant_rls('assessment_cycle_closure_reports');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM assessment_cycle_closure_reports LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back assessment closure reports while report rows exist';
    END IF;
END;
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS assessment_cycle_closure_reports;
