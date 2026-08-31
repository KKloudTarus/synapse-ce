-- +goose Up
-- #635 privacy & data governance: legal holds. An ACTIVE hold on an engagement suspends retention expiry
-- for that engagement's data (the retention deletion consults IsHeld and refuses while a hold is active).
-- Append-only history per (tenant, engagement): a released hold is kept for audit, so at most one row per
-- engagement is active (released_at IS NULL) — enforced by a partial unique index.

CREATE TABLE legal_holds (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    id            BIGSERIAL,
    engagement_id TEXT NOT NULL,
    reason        TEXT NOT NULL,
    placed_by     TEXT NOT NULL,
    placed_at     TIMESTAMPTZ NOT NULL,
    released_by   TEXT NOT NULL DEFAULT '',
    released_at   TIMESTAMPTZ NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT legal_holds_reason_not_blank CHECK (length(btrim(reason)) > 0),
    CONSTRAINT legal_holds_placed_by_not_blank CHECK (length(btrim(placed_by)) > 0)
);

-- At most one ACTIVE hold per engagement (release before re-placing a distinct one).
CREATE UNIQUE INDEX legal_holds_one_active_per_engagement
    ON legal_holds (tenant_id, engagement_id)
    WHERE released_at IS NULL;

CALL synapse_enable_tenant_rls('legal_holds');

-- +goose Down
DROP TABLE IF EXISTS legal_holds;
