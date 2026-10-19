-- +goose Up
CREATE TABLE ticket_external_observations (
 tenant_id TEXT NOT NULL REFERENCES tenants(id), integration_id TEXT NOT NULL, mapping_id TEXT NOT NULL,
 engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL, remote_id TEXT NOT NULL, status_category TEXT NOT NULL,
 provider_updated_at TIMESTAMPTZ, author_id TEXT NOT NULL DEFAULT '', deleted_or_unreadable BOOLEAN NOT NULL DEFAULT FALSE,
 checked_at TIMESTAMPTZ NOT NULL, version INTEGER NOT NULL DEFAULT 1 CHECK(version>0),
 PRIMARY KEY(tenant_id,mapping_id,engagement_id,finding_id,remote_id),
 FOREIGN KEY(tenant_id,mapping_id) REFERENCES ticket_mappings(tenant_id,id),
 FOREIGN KEY(tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id)
);
CREATE TABLE ticket_retest_proposals (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), integration_id TEXT NOT NULL,
 engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL, remote_id TEXT NOT NULL, observed_at TIMESTAMPTZ NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state='pending'),
 FOREIGN KEY(tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id)
);
CREATE INDEX ticket_retest_proposals_recent_idx ON ticket_retest_proposals(tenant_id,engagement_id,finding_id,observed_at DESC);
CREATE TABLE ticket_external_comments (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), integration_id TEXT NOT NULL,
 engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL, remote_id TEXT NOT NULL, author_id TEXT NOT NULL DEFAULT '',
 body TEXT NOT NULL CHECK(octet_length(body)<=16384), provider_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL,
 FOREIGN KEY(tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id)
);
CALL synapse_enable_tenant_rls('ticket_external_observations');
CALL synapse_enable_tenant_rls('ticket_retest_proposals');
CALL synapse_enable_tenant_rls('ticket_external_comments');
-- +goose Down
LOCK TABLE ticket_external_observations,ticket_retest_proposals,ticket_external_comments IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_external_observations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_retest_proposals NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_external_comments NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM ticket_external_observations) OR EXISTS (SELECT 1 FROM ticket_retest_proposals) OR EXISTS (SELECT 1 FROM ticket_external_comments) THEN
  RAISE EXCEPTION 'ticket inbound records must be retained; use a forward migration';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE ticket_external_comments,ticket_retest_proposals,ticket_external_observations;
