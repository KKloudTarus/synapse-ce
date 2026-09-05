-- +goose Up
-- Fleet host vulnerability context (#820). A Kind=host asset that reports installed OS packages gets
-- one hidden engagement, keyed here, that owns the packages as an imported SBOM and the CVE findings
-- the SCA pipeline derives from it. It mirrors the Project analysis context (0046): the row is
-- machine-owned, never listed as an operator engagement, and reached only through host_asset_id.
--
-- The column is nullable and unindexed for the common row, so existing engagements are untouched and
-- an old binary that does not know the column keeps inserting and reading rows unchanged.
ALTER TABLE engagements
    ADD COLUMN host_asset_id TEXT REFERENCES fleet_assets(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX idx_engagements_host_asset
    ON engagements(tenant_id, host_asset_id) WHERE host_asset_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_engagements_host_asset;
ALTER TABLE engagements DROP COLUMN IF EXISTS host_asset_id;
