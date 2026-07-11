-- +goose Up
-- E40.1 ingest (ADR-0023): the architecture-input threat model per engagement – a data-flow diagram
-- (components / data flows / trust boundaries / assets) the threat-modeling agent (E40.2) reasons over.
-- ONE row per engagement (the current model), stored as a validated JSONB blob (the domain
-- threatmodel.Model shape; the usecase bounds size + calls Model.Validate before every write). Unlike the
-- GLOBAL advisory corpus this is TENANT-SCOPED customer data: born with tenant_id so the P5/E22 row-scoping
-- sweep covers it with no backfill, while reads stay engagement-scoped via the tenant-gated child route
-- (mirrors judgments/findings). version bumps on each re-ingest (re-syncable, not append-only).
CREATE TABLE threat_models (
    engagement_id TEXT PRIMARY KEY REFERENCES engagements(id) ON DELETE CASCADE,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    data          JSONB NOT NULL,
    version       INTEGER NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_threat_models_tenant ON threat_models(tenant_id);

-- +goose Down
DROP TABLE IF EXISTS threat_models;
