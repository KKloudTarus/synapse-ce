-- +goose Up
ALTER TABLE dast_runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'verifier' CHECK (kind IN ('verifier','authenticated_scan'));
ALTER TABLE dast_runs ADD COLUMN scan_job_id TEXT;
ALTER TABLE dast_runs ADD COLUMN scan_fence BIGINT;
ALTER TABLE dast_runs ADD COLUMN scan_payload_sha256 TEXT;
ALTER TABLE dast_runs DROP CONSTRAINT dast_runs_status_check;
ALTER TABLE dast_runs DROP CONSTRAINT dast_runs_check;
ALTER TABLE dast_runs ADD CONSTRAINT dast_runs_status_check CHECK (status IN ('queued','running','succeeded','incomplete','failed'));
ALTER TABLE dast_runs ADD CONSTRAINT dast_runs_terminal_check CHECK ((status IN ('succeeded','incomplete','failed')) = (finished_at IS NOT NULL));
ALTER TABLE dast_runs ADD CONSTRAINT dast_runs_kind_status_check CHECK (kind = 'authenticated_scan' OR status <> 'incomplete');
ALTER TABLE dast_runs ADD CONSTRAINT dast_runs_scan_owner_check CHECK ((kind = 'verifier' AND scan_job_id IS NULL AND scan_fence IS NULL) OR (kind = 'authenticated_scan' AND scan_job_id IS NOT NULL AND scan_job_id <> '' AND (scan_fence IS NULL OR scan_fence > 0)));
ALTER TABLE dast_runs ADD CONSTRAINT dast_runs_scan_payload_check CHECK ((kind = 'verifier' AND scan_payload_sha256 IS NULL) OR (kind = 'authenticated_scan' AND scan_payload_sha256 IS NOT NULL AND scan_payload_sha256 ~ '^[0-9a-f]{64}$'));
ALTER TABLE dast_runs ADD CONSTRAINT dast_runs_scan_result_check CHECK (kind <> 'authenticated_scan' OR (verdict = '' AND http_status = 0 AND (status NOT IN ('succeeded','incomplete') OR evidence_id <> '')));
CREATE UNIQUE INDEX idx_dast_runs_scan_job ON dast_runs(tenant_id, scan_job_id) WHERE scan_job_id IS NOT NULL;

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE tenant_key TEXT; previous_tenant TEXT := current_setting('app.current_tenant', true);
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'DAST rollback requires read committed isolation';
    END IF;
    LOCK TABLE agent_approvals IN ACCESS EXCLUSIVE MODE;
    LOCK TABLE dast_runs IN ACCESS EXCLUSIVE MODE;
    FOR tenant_key IN SELECT id FROM tenants WHERE id <> '' LOOP
        PERFORM set_config('app.current_tenant', tenant_key, true);
        IF EXISTS (SELECT 1 FROM dast_runs WHERE tenant_id = tenant_key AND kind = 'authenticated_scan')
           OR EXISTS (SELECT 1 FROM agent_approvals WHERE tenant_id = tenant_key AND tool = 'run_authenticated_dast' AND consumed_by_dast_run_id IS NOT NULL) THEN
            RAISE EXCEPTION 'cannot remove authenticated DAST run authority';
        END IF;
    END LOOP;
    PERFORM set_config('app.current_tenant', COALESCE(previous_tenant, ''), true);
END $$;
-- +goose StatementEnd
DROP INDEX idx_dast_runs_scan_job;
ALTER TABLE dast_runs DROP CONSTRAINT dast_runs_scan_payload_check;
ALTER TABLE dast_runs DROP CONSTRAINT dast_runs_scan_result_check;
ALTER TABLE dast_runs DROP CONSTRAINT dast_runs_scan_owner_check;
ALTER TABLE dast_runs DROP CONSTRAINT dast_runs_kind_status_check;
ALTER TABLE dast_runs DROP CONSTRAINT dast_runs_terminal_check;
ALTER TABLE dast_runs DROP CONSTRAINT dast_runs_status_check;
ALTER TABLE dast_runs ADD CONSTRAINT dast_runs_status_check CHECK (status IN ('queued','running','succeeded','failed'));
ALTER TABLE dast_runs DROP COLUMN scan_payload_sha256;
ALTER TABLE dast_runs ADD CONSTRAINT dast_runs_check CHECK ((status IN ('succeeded','failed')) = (finished_at IS NOT NULL));
ALTER TABLE dast_runs DROP COLUMN scan_fence;
ALTER TABLE dast_runs DROP COLUMN scan_job_id;
ALTER TABLE dast_runs DROP COLUMN kind;
