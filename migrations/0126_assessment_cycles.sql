-- +goose Up
-- Phase A1 (#695): Assessment Cycle domain aggregate, schema, and membership tree.
-- Represents multi-phase assessment workflows with frozen boundary scoping and retest lineage.

CREATE TABLE assessment_cycles (
    tenant_id                   TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id                          TEXT NOT NULL,
    name                        TEXT NOT NULL,
    boundary_kind               TEXT NOT NULL,
    business_asset_id           TEXT NULL,
    project_id                  TEXT NULL,
    status                      TEXT NOT NULL,
    root_assessment_id          TEXT NOT NULL,
    selected_head_assessment_id TEXT NOT NULL,
    next_retest_number          INTEGER NOT NULL DEFAULT 1,
    version                     BIGINT NOT NULL DEFAULT 1,
    created_at                  TIMESTAMPTZ NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL,
    created_by                  TEXT NOT NULL DEFAULT '',
    updated_by                  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, business_asset_id) REFERENCES fleet_business_services(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, root_assessment_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, selected_head_assessment_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT assessment_cycles_boundary_kind_check CHECK (boundary_kind IN ('standalone', 'asset', 'project', 'asset_project')),
    CONSTRAINT assessment_cycles_status_check CHECK (status IN ('open', 'completed', 'archived')),
    CONSTRAINT assessment_cycles_next_retest_number_check CHECK (next_retest_number >= 1),
    CONSTRAINT assessment_cycles_version_check CHECK (version >= 1),
    CONSTRAINT assessment_cycles_boundary_check CHECK (
        (boundary_kind = 'standalone' AND business_asset_id IS NULL AND project_id IS NULL) OR
        (boundary_kind = 'asset' AND business_asset_id IS NOT NULL AND project_id IS NULL) OR
        (boundary_kind = 'project' AND business_asset_id IS NULL AND project_id IS NOT NULL) OR
        (boundary_kind = 'asset_project' AND business_asset_id IS NOT NULL AND project_id IS NOT NULL)
    )
);

CREATE TABLE assessment_cycle_members (
    tenant_id                   TEXT NOT NULL,
    cycle_id                    TEXT NOT NULL,
    assessment_id               TEXT NOT NULL,
    assessment_type             TEXT NOT NULL,
    predecessor_assessment_id   TEXT NULL,
    retest_number               INTEGER NOT NULL,
    relationship_version        BIGINT NOT NULL DEFAULT 1,
    created_at                  TIMESTAMPTZ NOT NULL,
    created_by                  TEXT NOT NULL DEFAULT '',
    archived_at                 TIMESTAMPTZ NULL,
    PRIMARY KEY (tenant_id, cycle_id, assessment_id),
    FOREIGN KEY (tenant_id, cycle_id) REFERENCES assessment_cycles(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, assessment_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, predecessor_assessment_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, assessment_id),
    CONSTRAINT assessment_cycle_members_type_check CHECK (assessment_type IN ('initial', 'retest')),
    CONSTRAINT assessment_cycle_members_retest_number_check CHECK (retest_number >= 0),
    CONSTRAINT assessment_cycle_members_relationship_version_check CHECK (relationship_version >= 1),
    CONSTRAINT assessment_cycle_members_root_check CHECK (
        (assessment_type = 'initial' AND predecessor_assessment_id IS NULL AND retest_number = 0 AND archived_at IS NULL) OR
        (assessment_type = 'retest' AND predecessor_assessment_id IS NOT NULL AND retest_number > 0)
    )
);

CREATE UNIQUE INDEX uq_assessment_cycle_members_initial ON assessment_cycle_members (tenant_id, cycle_id) WHERE assessment_type = 'initial';
CREATE UNIQUE INDEX uq_assessment_cycle_members_retest_number ON assessment_cycle_members (tenant_id, cycle_id, retest_number);
CREATE INDEX idx_assessment_cycle_members_lookup ON assessment_cycle_members (tenant_id, assessment_id);
CREATE INDEX idx_assessment_cycle_members_ordering ON assessment_cycle_members (tenant_id, cycle_id, retest_number ASC, assessment_id ASC);

CALL synapse_enable_tenant_rls('assessment_cycles');
CALL synapse_enable_tenant_rls('assessment_cycle_members');

-- +goose Down
DROP TABLE IF EXISTS assessment_cycle_members;
DROP TABLE IF EXISTS assessment_cycles;
