-- +goose Up
-- Finding-quality signals (Phase 1.95): component scope, metadata reachability,
-- action impact, and unified Synapse risk priority – so findings can be ranked
-- (production/direct/KEV first) and background (example/test) separated without
-- hiding anything. Defaults keep existing rows valid.
ALTER TABLE findings ADD COLUMN scope        TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE findings ADD COLUMN reachability TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE findings ADD COLUMN impact       TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN priority     INT  NOT NULL DEFAULT 3;

-- +goose Down
ALTER TABLE findings DROP COLUMN priority;
ALTER TABLE findings DROP COLUMN impact;
ALTER TABLE findings DROP COLUMN reachability;
ALTER TABLE findings DROP COLUMN scope;
