-- +goose Up
CREATE TABLE scan_run_comparison_evidence (
 tenant_id TEXT NOT NULL,
 run_id TEXT NOT NULL,
 content_hash TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
 payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 134217728),
 PRIMARY KEY (tenant_id,run_id),
 FOREIGN KEY (tenant_id,run_id) REFERENCES scan_runs(tenant_id,id) ON DELETE RESTRICT
);
CALL synapse_enable_tenant_rls('scan_run_comparison_evidence');
-- +goose StatementBegin
CREATE FUNCTION synapse_immutable_scan_comparison_evidence() RETURNS trigger AS $$
BEGIN
 RAISE EXCEPTION 'scan comparison evidence is immutable' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER scan_comparison_evidence_immutable BEFORE UPDATE OR DELETE ON scan_run_comparison_evidence
 FOR EACH ROW EXECUTE FUNCTION synapse_immutable_scan_comparison_evidence();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM scan_run_comparison_evidence) THEN
  RAISE EXCEPTION 'cannot roll back scan comparison evidence while evidence exists';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE scan_run_comparison_evidence;
DROP FUNCTION synapse_immutable_scan_comparison_evidence();
