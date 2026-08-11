-- +goose Up
-- Governed defensive response actions (issue #425). Each row records an action that changed a production
-- system under the SAME governance as an exploitation step: server-side admission, argv-only execution,
-- a human approval sealed into the evidence chain (approval_evidence_id links the sealed admission), a
-- mandatory reversal, and a declared blast radius. Tenant-scoped and RLS-enforced.
CREATE TABLE response_actions (
    tenant_id            TEXT NOT NULL REFERENCES tenants(id),
    id                   TEXT NOT NULL,
    engagement_id        TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind                 TEXT NOT NULL,
    target               TEXT NOT NULL,
    blast_radius         TEXT NOT NULL CHECK (blast_radius IN ('read_only', 'state_changing')),
    argv                 JSONB NOT NULL,
    -- The reversal is mandatory: a NOT NULL JSONB object that must name a reversal kind, mirroring the
    -- domain's construction-time refusal so a row that bypassed the domain cannot claim an irreversible
    -- action. (Reversibility is enforced in code + the catalogue drift test; this is defence in depth.)
    reversal             JSONB NOT NULL CHECK (reversal ? 'kind'),
    state                TEXT NOT NULL CHECK (state IN ('pending', 'applied', 'reverted', 'cancelled', 'violation')),
    approved_by          TEXT NOT NULL DEFAULT '',
    approval_evidence_id TEXT,
    applied_at           TIMESTAMPTZ,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX idx_response_actions_state ON response_actions (tenant_id, state);

CALL synapse_enable_tenant_rls('response_actions');

-- +goose Down
DROP TABLE response_actions;
