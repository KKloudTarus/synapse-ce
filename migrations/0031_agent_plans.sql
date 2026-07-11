-- +goose Up
-- Phase 4 hardening PR3 (ADR-0012): the LLM-proposed, Go-validated execution plan for an agent
-- session. ONE plan per session (session_id UNIQUE) so a redelivered Drive job cannot fork a
-- second plan. `revision` is an optimistic-concurrency token: a node-status change is a guarded
-- UPDATE (… WHERE revision=$expected) that bumps it, making a node claim an atomic CAS – the
-- durable idempotency authority that stops a redelivered/concurrent driver double-running a
-- node. `nodes` holds the DAG (id, tool, target, depends_on, status, action_id, risk) as JSONB;
-- the domain (agent.Plan) owns the structural invariants, this table just persists the bytes.
CREATE TABLE agent_plans (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT,
    session_id    TEXT NOT NULL UNIQUE REFERENCES agent_sessions(id) ON DELETE CASCADE,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    goal          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','active','complete','failed')),
    revision      INT  NOT NULL DEFAULT 1,
    nodes         JSONB NOT NULL DEFAULT '[]',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_plans_engagement ON agent_plans(engagement_id);

-- +goose Down
DROP TABLE agent_plans;
