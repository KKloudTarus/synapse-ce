-- +goose Up
-- Fleet agent identity (#409, epic #405): enrolled agents and the single-use enrolment tokens that
-- mint them. RLS-native via the 0057 procedure (tenant_id keys the policy; empty tenant = DENY, so
-- agents and tokens use non-empty tenant ids). Only credential HASHES are stored; the plaintext
-- enrolment token and agent bearer credential are shown once at creation and never persisted.
CREATE TABLE fleet_agents (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    name          TEXT NOT NULL,
    platform      TEXT NOT NULL DEFAULT '',
    os_version    TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    capabilities  JSONB NOT NULL DEFAULT '[]',
    token_hash    TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_fleet_agents_tenant ON fleet_agents (tenant_id, name);
CALL synapse_enable_tenant_rls('fleet_agents');

CREATE TABLE fleet_enrol_tokens (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    hash       TEXT NOT NULL,
    issued_by  TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, hash)
);
CALL synapse_enable_tenant_rls('fleet_enrol_tokens');

-- +goose Down
DROP TABLE fleet_enrol_tokens;
DROP TABLE fleet_agents;
