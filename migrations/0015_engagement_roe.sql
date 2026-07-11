-- +goose Up
-- Minimal rules of engagement (Phase 2, E1): allowed tool classes + blackout
-- windows, stored as JSON on the engagement. Empty default '{}' means no RoE
-- restriction (all tool classes, no blackout) – backward compatible with Phase 1
-- engagements. Enforced by the execution gate alongside scope + the auth window.
ALTER TABLE engagements ADD COLUMN roe JSONB NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE engagements DROP COLUMN roe;
