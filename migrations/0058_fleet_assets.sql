-- +goose Up
-- Fleet asset model (#431, epic #405): canonical assets, typed provenance-carrying edges, and a
-- business-service grouping. These are the FIRST tables to adopt Row Level Security via the 0057
-- procedure, which is what that migration was built for.
--
-- Tenancy invariant (see 0057): RLS-protected tables use NON-EMPTY tenant ids. The empty string
-- resolves to NULL under synapse_current_tenant() and means DENY, so the default single-tenant
-- deployment must supply a non-empty tenant id for these tables.
--
-- SECURITY: RLS is silently a no-op if the runtime DB role is SUPERUSER or has BYPASSRLS,
-- regardless of FORCE. The server MUST call postgres.CheckRLSRuntimeRole at startup when the
-- fleet asset model is enabled and refuse to serve on error (#431 requirement 6, #432). This
-- migration cannot enforce that; the composition root does.

CREATE TABLE fleet_assets (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    kind        TEXT NOT NULL,
    "key"       TEXT NOT NULL,
    name        TEXT NOT NULL,
    attributes  JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, kind, "key")
);
CREATE INDEX idx_fleet_assets_tenant_created ON fleet_assets(tenant_id, created_at DESC);
CALL synapse_enable_tenant_rls('fleet_assets');

CREATE TABLE fleet_asset_edges (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    from_asset TEXT NOT NULL,
    to_asset   TEXT NOT NULL,
    kind       TEXT NOT NULL,
    provenance TEXT NOT NULL,
    PRIMARY KEY (tenant_id, from_asset, to_asset, kind, provenance)
);
CALL synapse_enable_tenant_rls('fleet_asset_edges');

CREATE TABLE fleet_business_services (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    name       TEXT NOT NULL,
    owner      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CALL synapse_enable_tenant_rls('fleet_business_services');

-- +goose Down
DROP TABLE fleet_business_services;
DROP TABLE fleet_asset_edges;
DROP TABLE fleet_assets;
