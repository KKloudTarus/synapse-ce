-- +goose Up
-- Agent content-signing key registry (#607, A0.2). The public halves of the ed25519 keys an agent uses
-- to sign the CONTENT it ships (telemetry / detection / response), separate from the TLS/enrolment cert
-- key. The control plane resolves a key by the KeyID an incoming envelope names and decides — fail-closed
-- — whether it may admit the payload, so this table is the trust root for attributable agent content.
--
-- Invariants enforced here:
--   * key_id = fingerprint(public_key), and a row is immutable once written (provenance) — a KeyID can
--     never be re-pointed at a different key (anti-rollback);
--   * exactly one purpose per key (domain separation), CHECK-constrained;
--   * a bounded validity window (not_before < not_after), so rotation and expiry are meaningful;
--   * revocation is a monotonic, nullable timestamp — set once, never walked back.
-- Tenant isolation is by RLS (the 0057 procedure), identical to the other fleet tables.
CREATE TABLE agent_signing_keys (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    agent_id    TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    public_key  BYTEA NOT NULL,
    not_before  TIMESTAMPTZ NOT NULL,
    not_after   TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    replaced_by TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, key_id),
    CONSTRAINT agent_signing_keys_algorithm_check CHECK (algorithm = 'ed25519'),
    CONSTRAINT agent_signing_keys_purpose_check CHECK (purpose IN ('telemetry-batch', 'detection-batch', 'response-result')),
    CONSTRAINT agent_signing_keys_window_check CHECK (not_before < not_after)
);

CALL synapse_enable_tenant_rls('agent_signing_keys');

-- +goose Down
DROP TABLE agent_signing_keys;
