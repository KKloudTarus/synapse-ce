-- +goose Up
-- Project-level opt-in to writing the quality-gate result back to the forge (PR decoration, #1125).
-- Defaults false so no existing project performs an outward forge write until an operator enables it.
ALTER TABLE projects ADD COLUMN decorate_pull_requests BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE projects DROP COLUMN decorate_pull_requests;
