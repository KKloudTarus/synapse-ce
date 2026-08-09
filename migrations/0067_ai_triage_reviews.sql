-- +goose Up
-- P1.2: durable AI-triage human-review workflow.
-- Durable human-review queue for AI false-positive recommendations held by the
-- deterministic policy. The finding and scan remain authoritative and visible;
-- this row only records workflow state and the sealed scan-evidence reference.
ALTER TABLE evidence ADD CONSTRAINT evidence_tenant_engagement_id_unique
    UNIQUE (tenant_id, engagement_id, id);

CREATE TABLE ai_triage_reviews (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL REFERENCES tenants(id),
    engagement_id         TEXT NOT NULL,
    project_id            TEXT NOT NULL DEFAULT '',
    finding_id            TEXT NOT NULL,
    dedup_key             TEXT NOT NULL,
    title                 TEXT NOT NULL,
    severity              TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info','unknown')),
    cwe                   TEXT NOT NULL DEFAULT '',
    owner                 TEXT NOT NULL DEFAULT '',
    state                 TEXT NOT NULL CHECK (state IN ('pending','accepted','rejected')),
    verdict               TEXT NOT NULL,
    driver                TEXT NOT NULL,
    confidence            INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    suspected_fp          BOOLEAN NOT NULL,
    proposer_model        TEXT NOT NULL,
    verifier_model        TEXT NOT NULL DEFAULT '',
    prompt_version        TEXT NOT NULL,
    verified              BOOLEAN NOT NULL,
    verifier_verdict      TEXT NOT NULL DEFAULT '',
    verifier_driver       TEXT NOT NULL DEFAULT '',
    verifier_confidence   INTEGER NOT NULL DEFAULT 0 CHECK (verifier_confidence BETWEEN 0 AND 100),
    policy_version        TEXT NOT NULL,
    policy_reason         TEXT NOT NULL,
    shadow                BOOLEAN NOT NULL DEFAULT false,
    would_gate_exempt     BOOLEAN NOT NULL DEFAULT false,
    gate_exempt           BOOLEAN NOT NULL DEFAULT false,
    review_required       BOOLEAN NOT NULL DEFAULT true,
    evidence_ref          TEXT NOT NULL,
    decided_by            TEXT NOT NULL DEFAULT '',
    decision_rationale    TEXT NOT NULL DEFAULT '',
    decided_at            TIMESTAMPTZ,
    version               INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at            TIMESTAMPTZ NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, engagement_id, dedup_key, policy_version, prompt_version, proposer_model, verifier_model),
    FOREIGN KEY (tenant_id, engagement_id)
        REFERENCES engagements(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, engagement_id, finding_id)
        REFERENCES findings(tenant_id, engagement_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, engagement_id, evidence_ref)
        REFERENCES evidence(tenant_id, engagement_id, id),
    CHECK (dedup_key <> '' AND title <> '' AND proposer_model <> '' AND prompt_version <> ''
        AND policy_version <> '' AND policy_reason <> '' AND evidence_ref <> ''),
    CHECK (review_required AND NOT gate_exempt),
    CHECK (NOT would_gate_exempt OR shadow),
    CHECK ((state = 'pending' AND decided_by = '' AND decision_rationale = '' AND decided_at IS NULL)
        OR (state <> 'pending' AND decided_by <> '' AND decision_rationale <> '' AND decided_at IS NOT NULL))
);

CREATE INDEX ai_triage_reviews_queue ON ai_triage_reviews
    (tenant_id, state, severity, created_at DESC);
CREATE INDEX ai_triage_reviews_project ON ai_triage_reviews
    (tenant_id, project_id, state, created_at DESC);
CALL synapse_enable_tenant_rls('ai_triage_reviews');

-- +goose Down
DROP TABLE ai_triage_reviews;
ALTER TABLE evidence DROP CONSTRAINT evidence_tenant_engagement_id_unique;
