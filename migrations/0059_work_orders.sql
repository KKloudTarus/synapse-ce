-- +goose Up
-- Fleet work order model (#407, epic #405): addressed, signed, authorised units of work driven
-- through a state machine. RLS-native via the 0057 procedure (tenant_id keys the policy; empty
-- tenant = DENY, so orders use non-empty tenant ids).
--
-- asset_id, agent_id and authorization_id are logical cross-aggregate references validated at the
-- application layer, not DB foreign keys: the fleet agent table (#408) does not exist yet, and
-- work orders must be issuable before every referenced aggregate has its own table. tenant_id does
-- FK to tenants so RLS and tenant integrity hold.
CREATE TABLE work_orders (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    asset_id         TEXT NOT NULL,
    agent_id         TEXT NOT NULL,
    capability       TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    idempotency_key  TEXT NOT NULL,
    not_after        TIMESTAMPTZ NOT NULL,
    time_bucket      BIGINT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN
        ('issued','claimed','running','succeeded','failed','expired','cancelled','refused')),
    refuse_reason    TEXT NOT NULL DEFAULT '',
    signature        TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotent issue by (tenant, idempotency key).
CREATE UNIQUE INDEX work_orders_idem ON work_orders (tenant_id, idempotency_key);

-- At most one LIVE order per (tenant, asset, capability, time bucket): a second live order for the
-- same work is rejected, so duplicate scheduler ticks cannot double-dispatch.
CREATE UNIQUE INDEX work_orders_inflight ON work_orders (tenant_id, asset_id, capability, time_bucket)
    WHERE state IN ('issued', 'claimed', 'running');

CREATE INDEX work_orders_agent_state ON work_orders (tenant_id, agent_id, state);

CALL synapse_enable_tenant_rls('work_orders');

-- +goose Down
DROP TABLE work_orders;
