-- +goose Up
-- Edge confidence distinguishes direct inventory observations from relationships inferred from evidence.
ALTER TABLE fleet_asset_edges ADD COLUMN confidence TEXT;
UPDATE fleet_asset_edges SET confidence = 'inferred' WHERE confidence IS NULL;
ALTER TABLE fleet_asset_edges ALTER COLUMN confidence SET NOT NULL;
ALTER TABLE fleet_asset_edges
    ADD CONSTRAINT fleet_asset_edges_confidence_check CHECK (confidence IN ('observed', 'inferred'));

-- Derived, recomputable links from fleet assets to governed findings. This is not a second inventory:
-- both endpoints retain their canonical ids and the rows only cache producer-owned attribution evidence.
ALTER TABLE findings ADD CONSTRAINT findings_id_engagement_unique UNIQUE (id, engagement_id);

CREATE TABLE attack_path_edges (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    from_kind     TEXT NOT NULL CHECK (from_kind = 'asset'),
    from_id       TEXT NOT NULL,
    to_kind       TEXT NOT NULL CHECK (to_kind = 'finding'),
    to_id         TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind = 'affected_by'),
    provenance    TEXT NOT NULL CHECK (provenance <> ''),
    confidence    TEXT NOT NULL CHECK (confidence IN ('observed', 'inferred')),
    PRIMARY KEY (tenant_id, engagement_id, from_kind, from_id, to_kind, to_id, kind, provenance),
    FOREIGN KEY (tenant_id, from_id) REFERENCES fleet_assets(tenant_id, id),
    FOREIGN KEY (to_id, engagement_id) REFERENCES findings(id, engagement_id) ON DELETE CASCADE
);
CREATE INDEX attack_path_edges_tenant_finding ON attack_path_edges (tenant_id, to_id);
CALL synapse_enable_tenant_rls('attack_path_edges');

-- +goose StatementBegin
CREATE FUNCTION attack_path_edge_tenant_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM engagements e
        WHERE e.id = NEW.engagement_id
          AND COALESCE(NULLIF(e.tenant_id, ''), 'default') = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'attack path edge tenant does not own engagement';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER attack_path_edge_tenant_guard
    BEFORE INSERT OR UPDATE ON attack_path_edges
    FOR EACH ROW EXECUTE FUNCTION attack_path_edge_tenant_guard();

-- +goose Down
DROP TRIGGER attack_path_edge_tenant_guard ON attack_path_edges;
DROP FUNCTION attack_path_edge_tenant_guard();
DROP TABLE attack_path_edges;
ALTER TABLE findings DROP CONSTRAINT findings_id_engagement_unique;
ALTER TABLE fleet_asset_edges DROP CONSTRAINT fleet_asset_edges_confidence_check;
ALTER TABLE fleet_asset_edges DROP COLUMN confidence;
