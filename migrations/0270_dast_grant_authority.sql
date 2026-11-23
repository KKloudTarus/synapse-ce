-- +goose Up
ALTER TABLE agent_approvals ADD COLUMN consumed_by_dast_run_id TEXT;
ALTER TABLE agent_approvals ADD CONSTRAINT agent_approvals_dast_owner_consumed
    CHECK (consumed_by_dast_run_id IS NULL OR decision_state = 'consumed') NOT VALID;
ALTER TABLE agent_approvals VALIDATE CONSTRAINT agent_approvals_dast_owner_consumed;
ALTER TABLE dast_runs ADD COLUMN egress_grant_issued_at TIMESTAMPTZ;

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    tenant_key TEXT;
    previous_tenant TEXT := current_setting('app.current_tenant', true);
BEGIN
    LOCK TABLE agent_approvals IN ACCESS EXCLUSIVE MODE;
    LOCK TABLE dast_runs IN ACCESS EXCLUSIVE MODE;
    FOR tenant_key IN SELECT id FROM tenants WHERE id <> '' LOOP
        PERFORM set_config('app.current_tenant', tenant_key, true);
        IF EXISTS (SELECT 1 FROM agent_approvals WHERE tenant_id = tenant_key AND consumed_by_dast_run_id IS NOT NULL)
           OR EXISTS (SELECT 1 FROM dast_runs WHERE tenant_id = tenant_key AND egress_grant_issued_at IS NOT NULL) THEN
            RAISE EXCEPTION 'cannot drop DAST grant authority while ownership or issuance markers exist';
        END IF;
    END LOOP;
    PERFORM set_config('app.current_tenant', COALESCE(previous_tenant, ''), true);
END $$;
-- +goose StatementEnd
ALTER TABLE dast_runs DROP COLUMN egress_grant_issued_at;
ALTER TABLE agent_approvals DROP COLUMN consumed_by_dast_run_id;
