-- +goose Up
CREATE TABLE appsec_business_services (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    code TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, code)
);

CREATE TABLE appsec_assets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    identity_kind TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT '',
    exposure TEXT NOT NULL DEFAULT '',
    classification TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, category, identity_kind, identity_value)
);
CREATE INDEX appsec_assets_tenant_idx ON appsec_assets (tenant_id, name);

CREATE TABLE appsec_asset_versions (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES appsec_assets(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE (asset_id, value, source)
);

CREATE TABLE appsec_business_service_assets (
    business_service_id TEXT NOT NULL REFERENCES appsec_business_services(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES appsec_assets(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (business_service_id, asset_id)
);

CREATE TABLE appsec_asset_relationships (
    from_asset_id TEXT NOT NULL REFERENCES appsec_assets(id) ON DELETE CASCADE,
    to_asset_id TEXT NOT NULL REFERENCES appsec_assets(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (from_asset_id, to_asset_id, relationship_type),
    CHECK (from_asset_id <> to_asset_id)
);
CREATE INDEX appsec_asset_relationships_to_idx ON appsec_asset_relationships (to_asset_id);

-- +goose Down
DROP TABLE appsec_asset_relationships;
DROP TABLE appsec_business_service_assets;
DROP TABLE appsec_asset_versions;
DROP TABLE appsec_assets;
DROP TABLE appsec_business_services;
