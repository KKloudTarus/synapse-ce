-- +goose Up
-- OIDC identity and opaque browser-session persistence. Provider access/refresh tokens are never
-- stored here. New tables are RLS-protected and therefore require a non-empty tenant id.

-- A composite key lets tenant-scoped identity/session references prove that their user belongs to
-- the same tenant, rather than merely referring to an arbitrary globally-addressable user id.
ALTER TABLE users ADD CONSTRAINT users_tenant_id_id_unique UNIQUE (tenant_id, id);

CREATE TABLE oidc_external_identities (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id    TEXT NOT NULL,
    issuer     TEXT NOT NULL CHECK (btrim(issuer) <> ''),
    subject    TEXT NOT NULL CHECK (btrim(subject) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX idx_oidc_external_identities_tenant_user ON oidc_external_identities(tenant_id, user_id);
CALL synapse_enable_tenant_rls('oidc_external_identities');

CREATE TABLE oidc_authorization_transactions (
    id                       TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    state_hash               TEXT NOT NULL UNIQUE CHECK (btrim(state_hash) <> ''),
    nonce_hash               TEXT NOT NULL CHECK (btrim(nonce_hash) <> ''),
    pkce_verifier_ciphertext TEXT NOT NULL CHECK (btrim(pkce_verifier_ciphertext) <> ''),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at               TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX idx_oidc_authorization_transactions_expiry ON oidc_authorization_transactions(expires_at);
CALL synapse_enable_tenant_rls('oidc_authorization_transactions');

CREATE TABLE oidc_sessions (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id         TEXT NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE CHECK (btrim(token_hash) <> ''),
    csrf_token_hash TEXT NOT NULL CHECK (btrim(csrf_token_hash) <> ''),
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object' AND octet_length(metadata::text) <= 8192),
    -- origin_at is the immutable start of the session lineage (login); it is carried unchanged across
    -- rotations so the absolute-age cap is measured from first authentication, never reset by a poll.
    origin_at       TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK (updated_at >= created_at),
    CHECK (origin_at <= created_at),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX idx_oidc_sessions_tenant_user ON oidc_sessions(tenant_id, user_id);
CREATE INDEX idx_oidc_sessions_expiry ON oidc_sessions(expires_at) WHERE revoked_at IS NULL;
CALL synapse_enable_tenant_rls('oidc_sessions');

-- +goose Down
DROP TABLE IF EXISTS oidc_sessions;
DROP TABLE IF EXISTS oidc_authorization_transactions;
DROP TABLE IF EXISTS oidc_external_identities;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_id_id_unique;
