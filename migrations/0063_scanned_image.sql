-- +goose Up
-- Scanned-image digest index (#446): records which container-image manifest digests the engine has
-- already scanned, per tenant, so the Kubernetes cluster agent can correlate a running image digest
-- with a prior scan. A running digest absent from here is an honest coverage gap.
--
-- Tenancy invariant (see 0057/0058): RLS-protected tables use NON-EMPTY tenant ids; the empty string
-- resolves to NULL under synapse_current_tenant() and means DENY. The default single-tenant
-- deployment maps the empty tenant to 'default' (shared.TenantOrDefault / httpapi.DefaultFleetTenant);
-- the 'default' tenant row is seeded by 0058.
--
-- SECURITY: RLS is a no-op under a SUPERUSER/BYPASSRLS role regardless of FORCE. The composition root
-- calls postgres.CheckRLSRuntimeRole at startup when the fleet asset model is enabled and refuses to
-- serve on error; this migration cannot enforce that.

CREATE TABLE scanned_image (
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    digest           TEXT NOT NULL, -- container-image manifest digest, e.g. "sha256:…"
    first_scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, digest)
);
CALL synapse_enable_tenant_rls('scanned_image');

-- +goose Down
DROP TABLE scanned_image;
