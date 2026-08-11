-- +goose Up
-- Producer-owned current-state projection. Historical findings/assets remain governed by their existing
-- repositories; these rows decide whether a CSPM observation is active without resetting triage.
CREATE TABLE cspm_observations (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    engagement_id   TEXT NOT NULL,
    producer        TEXT NOT NULL,
    observation_kind TEXT NOT NULL CHECK (observation_kind IN ('asset','finding','edge')),
    object_id       TEXT NOT NULL,
    evidence_id     TEXT NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, engagement_id, producer, observation_kind, object_id),
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_cspm_observations_active ON cspm_observations(tenant_id, engagement_id, producer, active);
CALL synapse_enable_tenant_rls('cspm_observations');

-- +goose Down
DROP TABLE cspm_observations;
