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

-- Seed the non-empty default fleet tenant. RLS-protected tables cannot use the empty-string
-- default tenant (empty = DENY), so the single-tenant / default deployment maps the empty
-- principal tenant to 'default' (see httpapi.DefaultFleetTenant); this row satisfies the FK.
INSERT INTO tenants (id, name) VALUES ('default', 'default fleet tenant') ON CONFLICT (id) DO NOTHING;

CREATE TABLE fleet_assets (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    kind        TEXT NOT NULL,
    "key"       TEXT NOT NULL,
    name        TEXT NOT NULL,
    attributes  JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, kind, "key"),
    -- FK target for the composite edge references below (id is already unique via the PK, but a
    -- composite FK needs a unique constraint on exactly (tenant_id, id)).
    UNIQUE (tenant_id, id)
);
CREATE INDEX idx_fleet_assets_tenant_created ON fleet_assets(tenant_id, created_at DESC);
CALL synapse_enable_tenant_rls('fleet_assets');

-- Edges reference assets via a COMPOSITE FK that includes tenant_id, so an edge can only point at
-- assets in its own tenant. Referential-integrity checks bypass RLS in PostgreSQL, so the tenant_id
-- in the FK is what prevents a cross-tenant reference; it also rejects dangling edges.
CREATE TABLE fleet_asset_edges (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    from_asset TEXT NOT NULL,
    to_asset   TEXT NOT NULL,
    kind       TEXT NOT NULL,
    provenance TEXT NOT NULL,
    PRIMARY KEY (tenant_id, from_asset, to_asset, kind, provenance),
    FOREIGN KEY (tenant_id, from_asset) REFERENCES fleet_assets(tenant_id, id),
    FOREIGN KEY (tenant_id, to_asset) REFERENCES fleet_assets(tenant_id, id)
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
