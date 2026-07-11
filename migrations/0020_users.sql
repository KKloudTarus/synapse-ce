-- +goose Up
-- Phase 2.5 (FR-D2): real operator identities. Each consultant authenticates with
-- their own API key (only its SHA-256 is stored), so every action is attributable.
-- The bootstrap admin (id 'operator', keyed by SYNAPSE_API_TOKEN) is seeded in code
-- on startup – existing deployments keep working and historical "operator"
-- attribution stays valid (it now resolves to that user).
CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'member',
    api_key_hash TEXT NOT NULL,
    disabled     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_users_api_key_hash ON users(api_key_hash);

-- +goose Down
DROP TABLE users;
