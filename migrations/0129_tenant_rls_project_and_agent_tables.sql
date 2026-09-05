-- +goose Up
-- Epic #817: put the last thirteen tenant-scoped tables under forced Row Level Security.
--
-- The tables carried tenant_id since they were created, but their repositories ran on the raw
-- pool: no set_config('app.current_tenant'), and in several places (project_analysis_store,
-- approval_store) the tenant predicate was dropped entirely when the caller passed an empty
-- tenant. A compromised or buggy caller could therefore read another tenant's projects,
-- analyses, issues, hotspots, quality gates, threat models, agent sessions, approvals and plans.
-- The companion code change routes every one of those repositories through postgres.WithTenant
-- and keeps an explicit tenant_id = $n predicate as defense in depth.
--
-- DEPLOYMENT ORDERING - READ THIS BEFORE APPLYING.
--
-- This repository's normal order is migrate first, then deploy binaries. THIS MIGRATION INVERTS
-- THAT. FORCE ROW LEVEL SECURITY takes effect the instant it commits, and the runtime DB role is
-- not the table owner, so a binary that still queries these tables on the raw pool sees ZERO ROWS
-- and every write is rejected by WITH CHECK. Applying 0129 while the previous release is still
-- serving is a full outage of the project, quality-gate and agent surfaces, not a degradation.
--
-- Required operator sequence:
--   1. Deploy the binaries that route these thirteen tables through postgres.WithTenant
--      (the code change that ships with this file). Those binaries are correct against a
--      database with or without 0129 applied, so this step is safe on its own.
--   2. Confirm every replica, worker and helper process is on that build. A single old
--      synapse-api or synapse-worker left running will start failing at step 3.
--   3. Run synapse-migrate to apply 0129.
--
-- If your pipeline cannot run migrations after the deploy, hold this file for the release AFTER
-- the WithTenant code change rather than reordering it into the same window.
--
-- Rollback: the Down direction drops the policies and disables RLS, restoring the pre-0129
-- behaviour for old binaries. It does not undo the tenant_id backfill, which is forward-only
-- data repair and harmless to an old binary that ignores the column.

-- 1. agent_approvals and agent_plans were created (migrations 0028, 0031) with a nullable
--    tenant_id that no code path ever wrote, so every row holds NULL. RLS on a NULL tenant_id
--    denies the row to every tenant, so the column must be backfilled from the owning engagement
--    before the policy goes on, and pinned NOT NULL afterwards so a future insert cannot
--    reintroduce an unreachable row.
--
--    Migrations run as the table owner with no app.current_tenant set. engagements has had FORCE
--    ROW LEVEL SECURITY since 0057/0066, so a join against it would see zero rows and the backfill
--    would silently update nothing. Lift FORCE for this transaction and restore it inside the same
--    DO block: any failure rolls the whole goose transaction back, which restores FORCE with it.
--    RLS stays ENABLED throughout, so non-owner roles are governed the entire time.
-- +goose StatementBegin
DO $$
BEGIN
    EXECUTE 'ALTER TABLE engagements NO FORCE ROW LEVEL SECURITY';

    -- Strict: refuse to proceed if an approval or a plan has no resolvable engagement, or its
    -- engagement has an empty tenant. Fail closed rather than invent an owner for the row.
    PERFORM 1 FROM (
        SELECT a.action_id
          FROM agent_approvals a
     LEFT JOIN engagements e ON a.engagement_id = e.id
         WHERE e.id IS NULL OR e.tenant_id IS NULL OR e.tenant_id = ''
         LIMIT 1
    ) bad;
    IF FOUND THEN
        RAISE EXCEPTION 'agent_approvals tenant backfill: an approval has no resolvable engagement or its engagement tenant is empty';
    END IF;

    PERFORM 1 FROM (
        SELECT p.id
          FROM agent_plans p
     LEFT JOIN engagements e ON p.engagement_id = e.id
         WHERE e.id IS NULL OR e.tenant_id IS NULL OR e.tenant_id = ''
         LIMIT 1
    ) bad;
    IF FOUND THEN
        RAISE EXCEPTION 'agent_plans tenant backfill: a plan has no resolvable engagement or its engagement tenant is empty';
    END IF;

    -- Refuse to silently relabel a row that already claims a different owner.
    PERFORM 1 FROM (
        SELECT a.action_id
          FROM agent_approvals a
          JOIN engagements e ON a.engagement_id = e.id
         WHERE a.tenant_id IS NOT NULL AND a.tenant_id <> '' AND a.tenant_id <> e.tenant_id
         LIMIT 1
    ) bad;
    IF FOUND THEN
        RAISE EXCEPTION 'agent_approvals tenant backfill: an approval tenant_id conflicts with its engagement tenant';
    END IF;

    PERFORM 1 FROM (
        SELECT p.id
          FROM agent_plans p
          JOIN engagements e ON p.engagement_id = e.id
         WHERE p.tenant_id IS NOT NULL AND p.tenant_id <> '' AND p.tenant_id <> e.tenant_id
         LIMIT 1
    ) bad;
    IF FOUND THEN
        RAISE EXCEPTION 'agent_plans tenant backfill: a plan tenant_id conflicts with its engagement tenant';
    END IF;

    UPDATE agent_approvals a
       SET tenant_id = e.tenant_id
      FROM engagements e
     WHERE a.engagement_id = e.id
       AND (a.tenant_id IS NULL OR a.tenant_id = '');

    UPDATE agent_plans p
       SET tenant_id = e.tenant_id
      FROM engagements e
     WHERE p.engagement_id = e.id
       AND (p.tenant_id IS NULL OR p.tenant_id = '');

    EXECUTE 'ALTER TABLE engagements FORCE ROW LEVEL SECURITY';
END $$;
-- +goose StatementEnd

ALTER TABLE agent_approvals ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE agent_approvals ADD CONSTRAINT agent_approvals_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE agent_plans ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE agent_plans ADD CONSTRAINT agent_plans_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id);

-- Per-tenant lookup indexes for the predicates the converted stores now always carry.
CREATE INDEX idx_agent_approvals_tenant_pending ON agent_approvals(tenant_id, engagement_id) WHERE decision_state = 'pending';
CREATE INDEX idx_agent_plans_tenant_session ON agent_plans(tenant_id, session_id);

-- 2. Normalize any row still on the legacy empty-string tenant. Migration 0066 swept every
--    tenant_id column once; a binary released between 0066 and this change could have written a
--    new '' row. Under RLS the empty string resolves to NULL, which is DENY, so an unswept row
--    would be permanently invisible rather than merely mislabelled.
UPDATE projects                      SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE project_analyses              SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE project_analysis_hotspots     SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE project_hotspots              SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE project_hotspot_review_events SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE project_issues                SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE project_issue_review_events   SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE quality_gates                 SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE quality_profiles              SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE threat_models                 SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE agent_sessions                SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE agent_approvals               SET tenant_id = 'default' WHERE tenant_id = '';
UPDATE agent_plans                   SET tenant_id = 'default' WHERE tenant_id = '';

-- 3. The policies. synapse_enable_tenant_rls (migration 0057) applies the identical,
--    non-weakenable shape to each table: ENABLE, FORCE, and one USING + WITH CHECK policy named
--    <table>_tenant_isolation keyed on synapse_current_tenant().
CALL synapse_enable_tenant_rls('projects');
CALL synapse_enable_tenant_rls('project_analyses');
CALL synapse_enable_tenant_rls('project_analysis_hotspots');
CALL synapse_enable_tenant_rls('project_hotspots');
CALL synapse_enable_tenant_rls('project_hotspot_review_events');
CALL synapse_enable_tenant_rls('project_issues');
CALL synapse_enable_tenant_rls('project_issue_review_events');
CALL synapse_enable_tenant_rls('quality_gates');
CALL synapse_enable_tenant_rls('quality_profiles');
CALL synapse_enable_tenant_rls('threat_models');
CALL synapse_enable_tenant_rls('agent_sessions');
CALL synapse_enable_tenant_rls('agent_approvals');
CALL synapse_enable_tenant_rls('agent_plans');

-- +goose Down
-- Reverse in dependency order. Dropping the policy and disabling RLS restores the pre-0129
-- visibility a rolled-back binary expects. The tenant_id backfill is deliberately NOT reversed:
-- re-NULLing it would recreate the unreachable rows this migration repaired.
DROP POLICY IF EXISTS agent_plans_tenant_isolation ON agent_plans;
ALTER TABLE agent_plans NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_plans DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_approvals_tenant_isolation ON agent_approvals;
ALTER TABLE agent_approvals NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_approvals DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_sessions_tenant_isolation ON agent_sessions;
ALTER TABLE agent_sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_sessions DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS threat_models_tenant_isolation ON threat_models;
ALTER TABLE threat_models NO FORCE ROW LEVEL SECURITY;
ALTER TABLE threat_models DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS quality_profiles_tenant_isolation ON quality_profiles;
ALTER TABLE quality_profiles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE quality_profiles DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS quality_gates_tenant_isolation ON quality_gates;
ALTER TABLE quality_gates NO FORCE ROW LEVEL SECURITY;
ALTER TABLE quality_gates DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_issue_review_events_tenant_isolation ON project_issue_review_events;
ALTER TABLE project_issue_review_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_issue_review_events DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_issues_tenant_isolation ON project_issues;
ALTER TABLE project_issues NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_issues DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_hotspot_review_events_tenant_isolation ON project_hotspot_review_events;
ALTER TABLE project_hotspot_review_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_hotspot_review_events DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_hotspots_tenant_isolation ON project_hotspots;
ALTER TABLE project_hotspots NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_hotspots DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_analysis_hotspots_tenant_isolation ON project_analysis_hotspots;
ALTER TABLE project_analysis_hotspots NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_analysis_hotspots DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_analyses_tenant_isolation ON project_analyses;
ALTER TABLE project_analyses NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_analyses DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS projects_tenant_isolation ON projects;
ALTER TABLE projects NO FORCE ROW LEVEL SECURITY;
ALTER TABLE projects DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS idx_agent_plans_tenant_session;
DROP INDEX IF EXISTS idx_agent_approvals_tenant_pending;
ALTER TABLE agent_plans DROP CONSTRAINT IF EXISTS agent_plans_tenant_fk;
ALTER TABLE agent_plans ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE agent_approvals DROP CONSTRAINT IF EXISTS agent_approvals_tenant_fk;
ALTER TABLE agent_approvals ALTER COLUMN tenant_id DROP NOT NULL;
