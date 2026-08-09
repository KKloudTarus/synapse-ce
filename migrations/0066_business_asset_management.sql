-- +goose Up
-- Asset Management (#352), after fleet rollout migration 0065: evolve fleet_business_services into the durable
-- business-level Asset while preserving its IDs and the technical /api/v1/assets model.

INSERT INTO tenants (id, name) VALUES ('default', 'default tenant') ON CONFLICT (id) DO NOTHING;

-- Normalize the legacy empty single-tenant partition before adding tenant-aware relationships.
-- The empty tenant row is retained for backward compatibility with old offline tools, but all
-- existing tenant-owned rows move to the RLS-safe non-empty default partition.
-- Evidence and audit tenant_id are not part of their custody hashes, so this metadata-only
-- migration preserves chain validity while temporarily suspending their append-only UPDATE guard.
ALTER TABLE evidence DISABLE TRIGGER evidence_append_only;
ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only;
-- +goose StatementBegin
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT table_name FROM information_schema.columns WHERE table_schema='public' AND column_name='tenant_id'
  LOOP
    EXECUTE format('UPDATE %I SET tenant_id = ''default'' WHERE tenant_id = ''''', r.table_name);
  END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE evidence ENABLE TRIGGER evidence_append_only;
ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only;

ALTER TABLE fleet_business_services
  ADD COLUMN "key" TEXT,
  ADD COLUMN description TEXT NOT NULL DEFAULT '',
  ADD COLUMN asset_type TEXT NOT NULL DEFAULT 'business_service',
  ADD COLUMN criticality TEXT NOT NULL DEFAULT 'medium',
  ADD COLUMN lifecycle TEXT NOT NULL DEFAULT 'draft',
  ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}',
  ADD COLUMN version INT NOT NULL DEFAULT 1,
  ADD COLUMN created_by TEXT NOT NULL DEFAULT '',
  ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
UPDATE fleet_business_services SET "key" = id WHERE "key" IS NULL;
ALTER TABLE fleet_business_services ALTER COLUMN "key" SET NOT NULL;
ALTER TABLE fleet_business_services DROP CONSTRAINT fleet_business_services_tenant_id_name_key;
ALTER TABLE fleet_business_services ADD CONSTRAINT fleet_business_services_tenant_key_unique UNIQUE (tenant_id, "key");
ALTER TABLE fleet_business_services ADD CONSTRAINT fleet_business_services_tenant_id_unique UNIQUE (tenant_id, id);
ALTER TABLE fleet_business_services ADD CONSTRAINT fleet_business_services_type_check CHECK (asset_type IN ('product','application','system','business_service'));
ALTER TABLE fleet_business_services ADD CONSTRAINT fleet_business_services_criticality_check CHECK (criticality IN ('critical','high','medium','low'));
ALTER TABLE fleet_business_services ADD CONSTRAINT fleet_business_services_lifecycle_check CHECK (lifecycle IN ('draft','active','decommissioning','retired'));
ALTER TABLE fleet_business_services ADD CONSTRAINT fleet_business_services_version_check CHECK (version > 0);

ALTER TABLE projects ADD CONSTRAINT projects_tenant_id_unique UNIQUE (tenant_id, id);

CREATE TABLE business_asset_projects (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  business_asset_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  role TEXT NOT NULL,
  provenance TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, business_asset_id, project_id),
  FOREIGN KEY (tenant_id, business_asset_id) REFERENCES fleet_business_services(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  CHECK (role IN ('primary','supporting','dependency'))
);
CREATE INDEX idx_business_asset_projects_asset ON business_asset_projects(tenant_id, business_asset_id, role, project_id);
CALL synapse_enable_tenant_rls('business_asset_projects');

CREATE TABLE business_asset_technical_assets (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  business_asset_id TEXT NOT NULL,
  technical_asset_id TEXT NOT NULL,
  role TEXT NOT NULL,
  provenance TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, business_asset_id, technical_asset_id),
  FOREIGN KEY (tenant_id, business_asset_id) REFERENCES fleet_business_services(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, technical_asset_id) REFERENCES fleet_assets(tenant_id, id) ON DELETE RESTRICT,
  CHECK (role IN ('primary','supporting','dependency'))
);
CREATE INDEX idx_business_asset_technical_asset ON business_asset_technical_assets(tenant_id, business_asset_id, role, technical_asset_id);
CALL synapse_enable_tenant_rls('business_asset_technical_assets');

ALTER TABLE engagements ADD CONSTRAINT engagements_tenant_id_unique UNIQUE (tenant_id, id);
UPDATE agent_sessions s SET tenant_id = e.tenant_id FROM engagements e
  WHERE s.engagement_id = e.id AND (s.tenant_id IS NULL OR s.tenant_id = '');
ALTER TABLE agent_sessions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE agent_sessions ADD CONSTRAINT agent_sessions_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE agent_sessions ADD CONSTRAINT agent_sessions_tenant_id_unique UNIQUE (tenant_id, id);
ALTER TABLE agent_sessions ADD CONSTRAINT agent_sessions_engagement_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE;
CREATE INDEX idx_agent_sessions_tenant_resumable ON agent_sessions(tenant_id, updated_at)
  WHERE status IN ('running','awaiting_approval');
ALTER TABLE engagements ADD COLUMN business_asset_id TEXT;
ALTER TABLE engagements ADD CONSTRAINT engagements_business_asset_fk
  FOREIGN KEY (tenant_id, business_asset_id) REFERENCES fleet_business_services(tenant_id, id) ON DELETE RESTRICT;
CREATE INDEX idx_engagements_business_asset ON engagements(tenant_id, business_asset_id, updated_at DESC) WHERE business_asset_id IS NOT NULL;

ALTER TABLE scope_targets ADD COLUMN tenant_id TEXT;
UPDATE scope_targets st SET tenant_id = e.tenant_id FROM engagements e WHERE e.id = st.engagement_id;
ALTER TABLE scope_targets ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE scope_targets ADD CONSTRAINT scope_targets_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE scope_targets ADD CONSTRAINT scope_targets_engagement_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE;
CREATE INDEX idx_scope_targets_tenant_engagement ON scope_targets(tenant_id, engagement_id);

-- Retrofit the full Engagement assessment graph before enabling RLS. Composite foreign keys
-- prevent a tenant-scoped child from referencing a known parent ID owned by another tenant.
ALTER TABLE findings ADD CONSTRAINT findings_tenant_engagement_id_unique UNIQUE (tenant_id, engagement_id, id);
ALTER TABLE findings ADD CONSTRAINT findings_engagement_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE;
ALTER TABLE evidence ADD CONSTRAINT evidence_engagement_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE;
ALTER TABLE evidence ADD CONSTRAINT evidence_finding_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id, finding_id) REFERENCES findings(tenant_id, engagement_id, id);
ALTER TABLE finding_comments ADD CONSTRAINT finding_comments_engagement_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE;
ALTER TABLE finding_comments ADD CONSTRAINT finding_comments_finding_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id, finding_id) REFERENCES findings(tenant_id, engagement_id, id) ON DELETE CASCADE;
ALTER TABLE finding_retests ADD CONSTRAINT finding_retests_engagement_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE;
ALTER TABLE finding_retests ADD CONSTRAINT finding_retests_finding_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id, finding_id) REFERENCES findings(tenant_id, engagement_id, id) ON DELETE CASCADE;
ALTER TABLE imported_sboms ADD CONSTRAINT imported_sboms_engagement_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE;
ALTER TABLE writeup_drafts ADD CONSTRAINT writeup_drafts_engagement_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE;
ALTER TABLE writeup_drafts ADD CONSTRAINT writeup_drafts_finding_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id, finding_id) REFERENCES findings(tenant_id, engagement_id, id);

-- Durable jobs are tenant-owned. Existing opaque jobs are assigned to the migrated single-tenant
-- partition, but their old payloads still fail closed because handlers require a matching tenant_id.
ALTER TABLE jobs ADD COLUMN tenant_id TEXT REFERENCES tenants(id);
UPDATE jobs SET tenant_id = 'default' WHERE tenant_id IS NULL;
ALTER TABLE jobs ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_jobs_tenant_claimable ON jobs(tenant_id, available_at, id) WHERE status IN ('queued','claimed');

CALL synapse_enable_tenant_rls('engagements');
CALL synapse_enable_tenant_rls('scope_targets');
CALL synapse_enable_tenant_rls('findings');
CALL synapse_enable_tenant_rls('evidence');
CALL synapse_enable_tenant_rls('finding_comments');
CALL synapse_enable_tenant_rls('finding_retests');
CALL synapse_enable_tenant_rls('imported_sboms');
CALL synapse_enable_tenant_rls('writeup_drafts');
CALL synapse_enable_tenant_rls('jobs');

-- +goose Down
DROP POLICY jobs_tenant_isolation ON jobs;
ALTER TABLE jobs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE jobs DISABLE ROW LEVEL SECURITY;
DROP INDEX idx_jobs_tenant_claimable;
ALTER TABLE jobs DROP COLUMN tenant_id;
DROP POLICY writeup_drafts_tenant_isolation ON writeup_drafts;
ALTER TABLE writeup_drafts NO FORCE ROW LEVEL SECURITY;
ALTER TABLE writeup_drafts DISABLE ROW LEVEL SECURITY;
DROP POLICY imported_sboms_tenant_isolation ON imported_sboms;
ALTER TABLE imported_sboms NO FORCE ROW LEVEL SECURITY;
ALTER TABLE imported_sboms DISABLE ROW LEVEL SECURITY;
DROP POLICY finding_retests_tenant_isolation ON finding_retests;
ALTER TABLE finding_retests NO FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_retests DISABLE ROW LEVEL SECURITY;
DROP POLICY finding_comments_tenant_isolation ON finding_comments;
ALTER TABLE finding_comments NO FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_comments DISABLE ROW LEVEL SECURITY;
DROP POLICY evidence_tenant_isolation ON evidence;
ALTER TABLE evidence NO FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence DISABLE ROW LEVEL SECURITY;
DROP POLICY findings_tenant_isolation ON findings;
ALTER TABLE findings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;
DROP POLICY scope_targets_tenant_isolation ON scope_targets;
ALTER TABLE scope_targets NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scope_targets DISABLE ROW LEVEL SECURITY;
DROP POLICY engagements_tenant_isolation ON engagements;
ALTER TABLE engagements NO FORCE ROW LEVEL SECURITY;
ALTER TABLE engagements DISABLE ROW LEVEL SECURITY;
ALTER TABLE writeup_drafts DROP CONSTRAINT writeup_drafts_finding_fk_tenant;
ALTER TABLE writeup_drafts DROP CONSTRAINT writeup_drafts_engagement_fk_tenant;
ALTER TABLE imported_sboms DROP CONSTRAINT imported_sboms_engagement_fk_tenant;
ALTER TABLE finding_retests DROP CONSTRAINT finding_retests_finding_fk_tenant;
ALTER TABLE finding_retests DROP CONSTRAINT finding_retests_engagement_fk_tenant;
ALTER TABLE finding_comments DROP CONSTRAINT finding_comments_finding_fk_tenant;
ALTER TABLE finding_comments DROP CONSTRAINT finding_comments_engagement_fk_tenant;
ALTER TABLE evidence DROP CONSTRAINT evidence_finding_fk_tenant;
ALTER TABLE evidence DROP CONSTRAINT evidence_engagement_fk_tenant;
ALTER TABLE findings DROP CONSTRAINT findings_engagement_fk_tenant;
ALTER TABLE findings DROP CONSTRAINT findings_tenant_engagement_id_unique;
ALTER TABLE scope_targets DROP CONSTRAINT scope_targets_engagement_fk_tenant;
ALTER TABLE scope_targets DROP CONSTRAINT scope_targets_tenant_fk;
ALTER TABLE scope_targets DROP COLUMN tenant_id;
DROP INDEX IF EXISTS idx_engagements_business_asset;
ALTER TABLE engagements DROP CONSTRAINT engagements_business_asset_fk;
ALTER TABLE engagements DROP COLUMN business_asset_id;
DROP INDEX idx_agent_sessions_tenant_resumable;
ALTER TABLE agent_sessions DROP CONSTRAINT agent_sessions_engagement_fk_tenant;
ALTER TABLE agent_sessions DROP CONSTRAINT agent_sessions_tenant_id_unique;
ALTER TABLE agent_sessions DROP CONSTRAINT agent_sessions_tenant_fk;
ALTER TABLE agent_sessions ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE engagements DROP CONSTRAINT engagements_tenant_id_unique;
DROP TABLE business_asset_technical_assets;
DROP TABLE business_asset_projects;
ALTER TABLE projects DROP CONSTRAINT projects_tenant_id_unique;
ALTER TABLE fleet_business_services DROP CONSTRAINT fleet_business_services_version_check;
ALTER TABLE fleet_business_services DROP CONSTRAINT fleet_business_services_lifecycle_check;
ALTER TABLE fleet_business_services DROP CONSTRAINT fleet_business_services_criticality_check;
ALTER TABLE fleet_business_services DROP CONSTRAINT fleet_business_services_type_check;
ALTER TABLE fleet_business_services DROP CONSTRAINT fleet_business_services_tenant_id_unique;
ALTER TABLE fleet_business_services DROP CONSTRAINT fleet_business_services_tenant_key_unique;
ALTER TABLE fleet_business_services DROP COLUMN updated_by, DROP COLUMN created_by, DROP COLUMN version,
  DROP COLUMN metadata, DROP COLUMN lifecycle, DROP COLUMN criticality, DROP COLUMN asset_type,
  DROP COLUMN description, DROP COLUMN "key";
-- Restoring UNIQUE (tenant_id, name) can be IMPOSSIBLE, and for a reason this migration created: the Up
-- drops that constraint on purpose so two business assets may share a display name, keying them by
-- "key" instead. Once an operator has used that permission, the old constraint no longer describes the
-- data, and a bare ADD CONSTRAINT fails with a 23505 from the index build that names neither the rows
-- nor the reason -- which is what happens today the moment any two assets share a name.
--
-- So refuse with something an operator can act on, and say exactly which names collide. Leaving the
-- column silently non-unique instead would hand back a schema that is laxer than the one being rolled
-- back to, which is its own surprise.
-- +goose StatementBegin
DO $$
DECLARE conflicts text;
BEGIN
  SELECT string_agg(format('(%s, %s) x%s', tenant_id, name, n), ', ')
    INTO conflicts
    FROM (SELECT tenant_id, name, count(*) AS n FROM fleet_business_services
           GROUP BY tenant_id, name HAVING count(*) > 1) dup;
  IF conflicts IS NOT NULL THEN
    RAISE EXCEPTION 'cannot roll back migration 0066: UNIQUE (tenant_id, name) cannot be restored because assets now share a display name, which this migration made legal. Rename or remove the duplicates first: %', conflicts;
  END IF;
  ALTER TABLE fleet_business_services ADD CONSTRAINT fleet_business_services_tenant_id_name_key UNIQUE (tenant_id, name);
END $$;
-- +goose StatementEnd
