-- +goose Up
-- EPIC #860 D2.5: a GIN index over each advisory's alias array in the JSONB blob, so the owned matcher can
-- resolve the transitive alias closure of a scan's finding ids with a bounded, indexed query
-- (data->'Aliases' ?| array[...]) instead of a full-corpus scan. advisories are shared reference data (not
-- tenant-scoped), so the index is global. Backward-compatible and additive: it changes no column, and a
-- pre-0145 binary keeps reading and writing advisories unaffected. jsonb_ops supports the ?| operator.
CREATE INDEX IF NOT EXISTS idx_advisories_aliases ON advisories USING gin ((data -> 'Aliases'));

-- +goose Down
DROP INDEX IF EXISTS idx_advisories_aliases;
