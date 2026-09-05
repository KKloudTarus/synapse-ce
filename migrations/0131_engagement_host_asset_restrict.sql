-- +goose Up
-- A host context owns hash-chained evidence (imported SBOMs, scan results, findings). 0130 declared its
-- link to fleet_assets ON DELETE CASCADE, so an operational delete of a fleet asset would cascade
-- through the context into the ledger and remove sealed evidence without an audit trail. Evidence is
-- append-only; the asset row must not be deletable while a context refers to it.
ALTER TABLE engagements DROP CONSTRAINT IF EXISTS engagements_host_asset_id_fkey;
ALTER TABLE engagements
    ADD CONSTRAINT engagements_host_asset_id_fkey
    FOREIGN KEY (host_asset_id) REFERENCES fleet_assets(id) ON DELETE RESTRICT;

-- Operator engagement lists filter out both internal context kinds; once host contexts outnumber
-- operator engagements, the tenant index reads mostly rows it then discards. The partial index holds
-- exactly the rows those lists return.
CREATE INDEX IF NOT EXISTS idx_engagements_operator
    ON engagements(tenant_id, created_at DESC) WHERE project_id IS NULL AND host_asset_id IS NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_engagements_operator;
ALTER TABLE engagements DROP CONSTRAINT IF EXISTS engagements_host_asset_id_fkey;
ALTER TABLE engagements
    ADD CONSTRAINT engagements_host_asset_id_fkey
    FOREIGN KEY (host_asset_id) REFERENCES fleet_assets(id) ON DELETE CASCADE;
