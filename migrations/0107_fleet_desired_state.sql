-- +goose Up
-- Durable desired-vs-observed fleet intent (#633).
--
-- `fleet_agents.capabilities` is agent-reported observation and must never double as policy. Durable
-- intent is attached to the canonical host/cluster technical AssetID instead of the enrolment-scoped
-- AgentID: reinstalling or replacing an agent must not orphan the policy for the host/cluster it serves.
-- Asset kind remains authoritative in fleet_assets and is intentionally not duplicated here. The
-- mutation use case admits only host/cluster assets; the FK keeps every durable subject canonical.

CREATE FUNCTION synapse_fleet_desired_capabilities_valid(caps TEXT[])
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT
        array_ndims(caps) = 1
        AND cardinality(caps) BETWEEN 1 AND 64
        AND NOT EXISTS (
            SELECT 1
            FROM unnest(caps) AS c
            WHERE c IS NULL
               OR btrim(c) = ''
               OR c <> btrim(c)
               OR octet_length(c) > 128
               OR c ~ '[[:cntrl:]]'
        )
        AND cardinality(caps) = (SELECT count(DISTINCT c) FROM unnest(caps) AS c)
        AND caps = ARRAY(SELECT c FROM unnest(caps) AS c ORDER BY c COLLATE "C")
$$;

CREATE TABLE fleet_desired_state (
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    asset_id     TEXT NOT NULL CHECK (asset_id <> ''),
    policy_id    TEXT NOT NULL CHECK (policy_id <> ''),
    capabilities TEXT[] NOT NULL,
    updated_by   TEXT NOT NULL CHECK (btrim(updated_by) <> ''),
    version      BIGINT NOT NULL CHECK (version >= 1),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, asset_id),
    UNIQUE (tenant_id, policy_id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id),
    CONSTRAINT fleet_desired_state_capabilities_canonical CHECK (synapse_fleet_desired_capabilities_valid(capabilities)),
    CONSTRAINT fleet_desired_state_time_order CHECK (updated_at >= created_at)
);

CALL synapse_enable_tenant_rls('fleet_desired_state');

-- +goose Down
DROP TABLE fleet_desired_state;
DROP FUNCTION synapse_fleet_desired_capabilities_valid(TEXT[]);
