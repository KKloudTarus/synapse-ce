-- +goose Up
-- Risk-based remediation SLA governance (#80) and continuous-intelligence reassessment (#540).
-- Policies and assessments are append-only. Current pointers are separate so an audit can reproduce
-- every historical deadline. Human lifecycle state is isolated from machine-owned assessment refreshes.

CREATE TABLE sla_policies (
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    config_version TEXT NOT NULL,
    config         JSONB NOT NULL CHECK (jsonb_typeof(config) = 'object'),
    sha256         TEXT NOT NULL CHECK (length(sha256) = 64),
    created_by     TEXT NOT NULL CHECK (btrim(created_by) <> ''),
    created_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, config_version),
    UNIQUE (tenant_id, config_version, sha256),
    UNIQUE (tenant_id, sha256)
);

CREATE TABLE sla_active_policies (
    tenant_id      TEXT PRIMARY KEY REFERENCES tenants(id),
    config_version TEXT NOT NULL,
    activated_at   TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, config_version) REFERENCES sla_policies(tenant_id, config_version)
);

CREATE TABLE sla_assessments (
    tenant_id                 TEXT NOT NULL REFERENCES tenants(id),
    id                        TEXT NOT NULL,
    engagement_id             TEXT NOT NULL,
    finding_id                TEXT NOT NULL,
    source_risk_assessment_id TEXT,
    inputs                    JSONB NOT NULL CHECK (jsonb_typeof(inputs) = 'object'),
    result                    JSONB NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    input_hash                TEXT NOT NULL CHECK (length(input_hash) = 64),
    config_hash               TEXT NOT NULL CHECK (length(config_hash) = 64),
    config_version            TEXT NOT NULL,
    tier                      TEXT NOT NULL CHECK (tier IN ('emergency','critical','high','medium','low','exception')),
    score                     DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 100),
    mitigate_by               TIMESTAMPTZ NOT NULL,
    remediate_by              TIMESTAMPTZ NOT NULL,
    previous_assessment_id    TEXT,
    assessed_at               TIMESTAMPTZ NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, engagement_id, finding_id, id),
    UNIQUE (tenant_id, engagement_id, finding_id, config_version, input_hash),
    FOREIGN KEY (tenant_id, engagement_id, finding_id)
        REFERENCES findings(tenant_id, engagement_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, config_version, config_hash)
        REFERENCES sla_policies(tenant_id, config_version, sha256),
    FOREIGN KEY (tenant_id, source_risk_assessment_id)
        REFERENCES vulnerability_risk_assessments(tenant_id, id),
    FOREIGN KEY (tenant_id, engagement_id, finding_id, previous_assessment_id)
        REFERENCES sla_assessments(tenant_id, engagement_id, finding_id, id),
    CHECK (mitigate_by >= assessed_at),
    CHECK (remediate_by >= mitigate_by)
);
CREATE INDEX idx_sla_assessments_history
    ON sla_assessments(tenant_id, engagement_id, finding_id, assessed_at DESC, id DESC);
CREATE INDEX idx_sla_assessments_due
    ON sla_assessments(tenant_id, engagement_id, remediate_by, finding_id);

CREATE TABLE sla_current_assessments (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    engagement_id TEXT NOT NULL,
    finding_id    TEXT NOT NULL,
    assessment_id TEXT NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, engagement_id, finding_id),
    FOREIGN KEY (tenant_id, engagement_id, finding_id)
        REFERENCES findings(tenant_id, engagement_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, engagement_id, finding_id, assessment_id)
        REFERENCES sla_assessments(tenant_id, engagement_id, finding_id, id) ON DELETE CASCADE
);

CREATE TABLE sla_lifecycles (
    tenant_id              TEXT NOT NULL REFERENCES tenants(id),
    engagement_id          TEXT NOT NULL,
    finding_id             TEXT NOT NULL,
    assessment_id          TEXT NOT NULL,
    status                 TEXT NOT NULL CHECK (status IN ('open','mitigating','remediated','accepted_risk')),
    version                INT NOT NULL CHECK (version > 0),
    reason                 TEXT NOT NULL DEFAULT '',
    compensating_control   TEXT NOT NULL DEFAULT '',
    accepted_by            TEXT NOT NULL DEFAULT '',
    accepted_at            TIMESTAMPTZ,
    acceptance_expires_at  TIMESTAMPTZ,
    updated_by             TEXT NOT NULL CHECK (btrim(updated_by) <> ''),
    updated_at             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, engagement_id, finding_id),
    FOREIGN KEY (tenant_id, engagement_id, finding_id)
        REFERENCES findings(tenant_id, engagement_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, engagement_id, finding_id, assessment_id)
        REFERENCES sla_assessments(tenant_id, engagement_id, finding_id, id),
    CHECK (
        (status = 'accepted_risk' AND btrim(reason) <> '' AND btrim(compensating_control) <> ''
            AND btrim(accepted_by) <> '' AND accepted_at IS NOT NULL
            AND acceptance_expires_at IS NOT NULL AND acceptance_expires_at > accepted_at)
        OR
        (status <> 'accepted_risk' AND accepted_by = '' AND accepted_at IS NULL
            AND acceptance_expires_at IS NULL)
    )
);
CREATE INDEX idx_sla_lifecycles_state
    ON sla_lifecycles(tenant_id, engagement_id, status, updated_at DESC);
CREATE INDEX idx_sla_lifecycles_acceptance_expiry
    ON sla_lifecycles(tenant_id, acceptance_expires_at)
    WHERE status = 'accepted_risk';

CREATE TABLE sla_lifecycle_events (
    tenant_id              TEXT NOT NULL REFERENCES tenants(id),
    id                     TEXT NOT NULL,
    engagement_id          TEXT NOT NULL,
    finding_id             TEXT NOT NULL,
    assessment_id          TEXT NOT NULL,
    from_status            TEXT NOT NULL CHECK (from_status IN ('open','mitigating','remediated','accepted_risk')),
    to_status              TEXT NOT NULL CHECK (to_status IN ('open','mitigating','remediated','accepted_risk')),
    reason                 TEXT NOT NULL CHECK (btrim(reason) <> ''),
    compensating_control   TEXT NOT NULL DEFAULT '',
    acceptance_expires_at  TIMESTAMPTZ,
    actor                  TEXT NOT NULL CHECK (btrim(actor) <> ''),
    before_version         INT NOT NULL CHECK (before_version > 0),
    after_version          INT NOT NULL CHECK (after_version = before_version + 1),
    occurred_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, engagement_id, finding_id)
        REFERENCES sla_lifecycles(tenant_id, engagement_id, finding_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, engagement_id, finding_id, assessment_id)
        REFERENCES sla_assessments(tenant_id, engagement_id, finding_id, id)
);
CREATE INDEX idx_sla_lifecycle_events_history
    ON sla_lifecycle_events(tenant_id, engagement_id, finding_id, occurred_at, id);

CALL synapse_enable_tenant_rls('sla_policies');
CALL synapse_enable_tenant_rls('sla_active_policies');
CALL synapse_enable_tenant_rls('sla_assessments');
CALL synapse_enable_tenant_rls('sla_current_assessments');
CALL synapse_enable_tenant_rls('sla_lifecycles');
CALL synapse_enable_tenant_rls('sla_lifecycle_events');

-- +goose Down
DROP TABLE IF EXISTS sla_lifecycle_events;
DROP TABLE IF EXISTS sla_lifecycles;
DROP TABLE IF EXISTS sla_current_assessments;
DROP TABLE IF EXISTS sla_assessments;
DROP TABLE IF EXISTS sla_active_policies;
DROP TABLE IF EXISTS sla_policies;
