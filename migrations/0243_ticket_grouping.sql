-- +goose Up
ALTER TABLE ticket_mappings
    ADD COLUMN grouping_mode TEXT NOT NULL DEFAULT 'finding'
        CHECK (grouping_mode IN ('finding','vulnerability_project')),
    ADD CONSTRAINT ticket_mappings_grouping_detail CHECK (
        grouping_mode='finding' OR (project_id IS NOT NULL AND data_class='detail')
    ),
    ADD CONSTRAINT ticket_mappings_auto_push_minimum CHECK (
        NOT auto_push_enabled OR auto_push_min_severity IN ('info','low','medium','high','critical')
    );

-- A reservation serializes the first create for a mapping/project/CVE group.
-- Members preserve the finding identities that currently contribute to it.
CREATE TABLE ticket_groups (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    id TEXT NOT NULL,
    mapping_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    project_key TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    security_level TEXT NOT NULL,
    intent_id TEXT,
    remote_id TEXT NOT NULL DEFAULT '',
    remote_url TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,mapping_id,project_id,vulnerability_id),
    FOREIGN KEY(tenant_id,mapping_id) REFERENCES ticket_mappings(tenant_id,id),
    FOREIGN KEY(tenant_id,integration_id) REFERENCES integrations(tenant_id,id),
    FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id),
    FOREIGN KEY(tenant_id,intent_id) REFERENCES ticket_intents(tenant_id,id)
);
CREATE TABLE ticket_group_members (
    tenant_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(tenant_id,group_id,engagement_id,finding_id),
    FOREIGN KEY(tenant_id,group_id) REFERENCES ticket_groups(tenant_id,id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_id,engagement_id,finding_id) REFERENCES findings(tenant_id,engagement_id,id)
);
CALL synapse_enable_tenant_rls('ticket_groups');
CALL synapse_enable_tenant_rls('ticket_group_members');

-- +goose Down
LOCK TABLE ticket_mappings,ticket_groups,ticket_group_members IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_mappings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_groups NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_group_members NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ticket_groups) OR EXISTS(SELECT 1 FROM ticket_group_members)
    OR EXISTS(SELECT 1 FROM ticket_mappings WHERE grouping_mode<>'finding') THEN
  RAISE EXCEPTION 'cannot roll back ticket grouping while grouped data exists' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE ticket_groups FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_group_members FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_mappings FORCE ROW LEVEL SECURITY;
DROP TABLE ticket_group_members;
DROP TABLE ticket_groups;
ALTER TABLE ticket_mappings DROP CONSTRAINT ticket_mappings_auto_push_minimum, DROP CONSTRAINT ticket_mappings_grouping_detail, DROP COLUMN grouping_mode;
