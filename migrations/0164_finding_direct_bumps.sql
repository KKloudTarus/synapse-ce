-- +goose Up
-- Persist the minimal-upgrade remediation set on each finding (EPIC #860 D3.8): the direct (top-level)
-- dependencies to bump to remove a transitive vulnerability. Newline-separated refs in a TEXT column (a ref
-- never contains a newline); empty for findings with no upgrade path. Additive with a default, so every
-- existing row is valid and older binaries that do not write the column keep working (phased-safe).
ALTER TABLE findings ADD COLUMN direct_bumps TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE findings DROP COLUMN direct_bumps;
