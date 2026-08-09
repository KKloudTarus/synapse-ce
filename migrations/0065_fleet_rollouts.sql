-- +goose Up
-- Operator-controlled agent update rollout (#412 req 9).
--
-- The plan is DURABLE on purpose. Holding it in memory looks fail-closed — a lost plan offers no
-- update — but it fails closed SILENTLY: a fleet mid-canary on 1.4.0 stops being offered anything the
-- moment the control plane restarts, and nothing says why. That is the same "unexplainable silence"
-- this feature is built to avoid, so the plan survives a restart and an operator's decision stays on
-- the record.
--
-- One row per (tenant, channel). RLS-native via the 0057 procedure; the empty tenant means DENY there,
-- so plans use non-empty tenant ids like every other fleet table.
CREATE TABLE fleet_rollouts (
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    channel        TEXT NOT NULL CHECK (channel <> ''),
    -- Empty target = a resting plan: configured, but offering nothing. It is a legitimate state and
    -- distinct from "no plan at all", which is the absence of a row.
    target_version TEXT NOT NULL DEFAULT '',
    -- Canary groups that receive the target FIRST, stored sorted and deduplicated by the domain so one
    -- intent has one representation.
    canary_groups  TEXT[] NOT NULL DEFAULT '{}',
    -- Promotion is the operator's SECOND deliberate action: the canary held, so every other group may
    -- now receive the target. A promoted plan with no canary group is impossible by construction
    -- (the domain refuses it), because that would mean every host at once.
    promoted_to_all BOOLEAN NOT NULL DEFAULT false,
    paused          BOOLEAN NOT NULL DEFAULT false,
    -- A pause without a reason makes a stopped fleet indistinguishable from a broken one, so the
    -- reason is required whenever paused. Enforced here as well as in the domain: the constraint is
    -- the thing that survives a future second writer.
    pause_reason   TEXT NOT NULL DEFAULT '',
    updated_by     TEXT NOT NULL CHECK (updated_by <> ''),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, channel),
    CONSTRAINT fleet_rollouts_pause_needs_reason CHECK (NOT paused OR pause_reason <> ''),
    CONSTRAINT fleet_rollouts_promotion_needs_target CHECK (NOT promoted_to_all OR target_version <> ''),
    CONSTRAINT fleet_rollouts_promotion_needs_canary CHECK (NOT promoted_to_all OR cardinality(canary_groups) > 0)
);

CALL synapse_enable_tenant_rls('fleet_rollouts');

-- +goose Down
DROP TABLE fleet_rollouts;
