-- +goose Up
-- Bounded tenant-owned AppSec inventory. Assets retain a stable category/identity
-- pair; shared infrastructure is linked to many business services instead of
-- duplicated. Child RLS policies derive tenancy from their asset/service parent.
CREATE TABLE appsec_assets (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    name           TEXT NOT NULL,
    category       TEXT NOT NULL,
    identity_kind  TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    lifecycle      TEXT NOT NULL,
    criticality    TEXT NOT NULL,
    exposure       TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT '',
    version        INTEGER NOT NULL CHECK (version > 0),
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL,
    created_by     TEXT NOT NULL DEFAULT '',
    updated_by     TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, category, identity_kind, identity_value)
);
CREATE INDEX appsec_assets_tenant_category_idx ON appsec_assets (tenant_id, category, name);

CREATE TABLE appsec_asset_versions (
    id         TEXT PRIMARY KEY,
    asset_id   TEXT NOT NULL REFERENCES appsec_assets(id) ON DELETE CASCADE,
    tenant_id  TEXT NOT NULL,
    number     INTEGER NOT NULL CHECK (number > 0),
    snapshot   JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    UNIQUE (asset_id, number)
);

CREATE TABLE appsec_business_services (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL,
    lifecycle   TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    created_by  TEXT NOT NULL DEFAULT '',
    updated_by  TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, name)
);

CREATE TABLE appsec_business_service_assets (
    business_service_id TEXT NOT NULL REFERENCES appsec_business_services(id) ON DELETE CASCADE,
    asset_id            TEXT NOT NULL REFERENCES appsec_assets(id) ON DELETE CASCADE,
    role                TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    created_by          TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (business_service_id, asset_id)
);
CREATE INDEX appsec_business_service_assets_asset_idx ON appsec_business_service_assets (asset_id);

CREATE TABLE appsec_asset_relationships (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    from_asset_id TEXT NOT NULL REFERENCES appsec_assets(id) ON DELETE CASCADE,
    to_asset_id   TEXT NOT NULL REFERENCES appsec_assets(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    created_by    TEXT NOT NULL DEFAULT '',
    CHECK (from_asset_id <> to_asset_id),
    UNIQUE (from_asset_id, to_asset_id, relation_type)
);
CREATE INDEX appsec_asset_relationships_from_idx ON appsec_asset_relationships (from_asset_id);

CREATE TABLE appsec_asset_ownership_assignments (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    asset_id   TEXT NOT NULL REFERENCES appsec_assets(id) ON DELETE CASCADE,
    principal  TEXT NOT NULL,
    role       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    UNIQUE (asset_id, principal, role)
);

ALTER TABLE appsec_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON appsec_assets USING (tenant_id = synapse_current_tenant_id()) WITH CHECK (tenant_id = synapse_current_tenant_id());
ALTER TABLE appsec_asset_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec_asset_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_parent_tenant_isolation ON appsec_asset_versions
USING (EXISTS (SELECT 1 FROM appsec_assets a WHERE a.id = asset_id AND a.tenant_id = synapse_current_tenant_id()))
WITH CHECK (tenant_id = synapse_current_tenant_id() AND EXISTS (SELECT 1 FROM appsec_assets a WHERE a.id = asset_id AND a.tenant_id = synapse_current_tenant_id()));
ALTER TABLE appsec_business_services ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec_business_services FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_tenant_isolation ON appsec_business_services USING (tenant_id = synapse_current_tenant_id()) WITH CHECK (tenant_id = synapse_current_tenant_id());
ALTER TABLE appsec_business_service_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec_business_service_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_parent_tenant_isolation ON appsec_business_service_assets
USING (EXISTS (SELECT 1 FROM appsec_business_services s WHERE s.id = business_service_id AND s.tenant_id = synapse_current_tenant_id()))
WITH CHECK (EXISTS (SELECT 1 FROM appsec_business_services s WHERE s.id = business_service_id AND s.tenant_id = synapse_current_tenant_id()) AND EXISTS (SELECT 1 FROM appsec_assets a WHERE a.id = asset_id AND a.tenant_id = synapse_current_tenant_id()));
ALTER TABLE appsec_asset_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec_asset_relationships FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_parent_tenant_isolation ON appsec_asset_relationships
USING (EXISTS (SELECT 1 FROM appsec_assets a WHERE a.id = from_asset_id AND a.tenant_id = synapse_current_tenant_id()))
WITH CHECK (tenant_id = synapse_current_tenant_id() AND EXISTS (SELECT 1 FROM appsec_assets a WHERE a.id = from_asset_id AND a.tenant_id = synapse_current_tenant_id()) AND EXISTS (SELECT 1 FROM appsec_assets a WHERE a.id = to_asset_id AND a.tenant_id = synapse_current_tenant_id()));
ALTER TABLE appsec_asset_ownership_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE appsec_asset_ownership_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY synapse_parent_tenant_isolation ON appsec_asset_ownership_assignments
USING (EXISTS (SELECT 1 FROM appsec_assets a WHERE a.id = asset_id AND a.tenant_id = synapse_current_tenant_id()))
WITH CHECK (tenant_id = synapse_current_tenant_id() AND EXISTS (SELECT 1 FROM appsec_assets a WHERE a.id = asset_id AND a.tenant_id = synapse_current_tenant_id()));

-- +goose Down
DROP POLICY synapse_parent_tenant_isolation ON appsec_asset_ownership_assignments;
ALTER TABLE appsec_asset_ownership_assignments NO FORCE ROW LEVEL SECURITY;
ALTER TABLE appsec_asset_ownership_assignments DISABLE ROW LEVEL SECURITY;
DROP TABLE appsec_asset_ownership_assignments;
DROP POLICY synapse_parent_tenant_isolation ON appsec_asset_relationships;
ALTER TABLE appsec_asset_relationships NO FORCE ROW LEVEL SECURITY;
ALTER TABLE appsec_asset_relationships DISABLE ROW LEVEL SECURITY;
DROP TABLE appsec_asset_relationships;
DROP POLICY synapse_parent_tenant_isolation ON appsec_business_service_assets;
ALTER TABLE appsec_business_service_assets NO FORCE ROW LEVEL SECURITY;
ALTER TABLE appsec_business_service_assets DISABLE ROW LEVEL SECURITY;
DROP TABLE appsec_business_service_assets;
DROP POLICY synapse_tenant_isolation ON appsec_business_services;
ALTER TABLE appsec_business_services NO FORCE ROW LEVEL SECURITY;
ALTER TABLE appsec_business_services DISABLE ROW LEVEL SECURITY;
DROP TABLE appsec_business_services;
DROP POLICY synapse_parent_tenant_isolation ON appsec_asset_versions;
ALTER TABLE appsec_asset_versions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE appsec_asset_versions DISABLE ROW LEVEL SECURITY;
DROP TABLE appsec_asset_versions;
DROP POLICY synapse_tenant_isolation ON appsec_assets;
ALTER TABLE appsec_assets NO FORCE ROW LEVEL SECURITY;
ALTER TABLE appsec_assets DISABLE ROW LEVEL SECURITY;
DROP TABLE appsec_assets;
