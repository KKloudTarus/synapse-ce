-- +goose Up
-- Backfill durable execution records from their immutable engagement/session parent
-- before applying RLS in the follow-up migration. Queue rows stay nullable during
-- transition because historic opaque payloads cannot establish a trustworthy tenant.
ALTER TABLE agent_messages ADD COLUMN tenant_id TEXT;
UPDATE agent_messages m SET tenant_id = s.tenant_id FROM agent_sessions s WHERE s.id = m.session_id;
ALTER TABLE agent_messages ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE agent_decisions ADD COLUMN tenant_id TEXT;
UPDATE agent_decisions d SET tenant_id = s.tenant_id FROM agent_sessions s WHERE s.id = d.session_id;
ALTER TABLE agent_decisions ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE recon_runs ADD COLUMN tenant_id TEXT;
UPDATE recon_runs r SET tenant_id = e.tenant_id FROM engagements e WHERE e.id = r.engagement_id;
ALTER TABLE recon_runs ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE scan_jobs ADD COLUMN tenant_id TEXT;
UPDATE scan_jobs j SET tenant_id = e.tenant_id FROM engagements e WHERE e.id = j.engagement_id;
ALTER TABLE scan_jobs ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE scan_runs ADD COLUMN tenant_id TEXT;
UPDATE scan_runs r SET tenant_id = e.tenant_id FROM engagements e WHERE e.id = r.engagement_id;
ALTER TABLE scan_runs ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE jobs ADD COLUMN tenant_id TEXT;
CREATE INDEX idx_jobs_tenant_claimable ON jobs (tenant_id, available_at) WHERE status <> 'done';

-- +goose Down
DROP INDEX idx_jobs_tenant_claimable;
ALTER TABLE jobs DROP COLUMN tenant_id;
ALTER TABLE scan_runs DROP COLUMN tenant_id;
ALTER TABLE scan_jobs DROP COLUMN tenant_id;
ALTER TABLE recon_runs DROP COLUMN tenant_id;
ALTER TABLE agent_decisions DROP COLUMN tenant_id;
ALTER TABLE agent_messages DROP COLUMN tenant_id;
