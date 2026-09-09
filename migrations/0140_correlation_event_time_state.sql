-- +goose Up
-- #676 durable two-phase event-time correlation checkpoint, staging, and immutable assignments.
CREATE TABLE correlation_checkpoints (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    engagement_id   TEXT NOT NULL,
    revision        BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    max_observed_at TIMESTAMPTZ,
    watermark       TIMESTAMPTZ,
    phase           TEXT NOT NULL DEFAULT '' CHECK (phase IN ('', 'source', 'consume')),
    completed_recorded_at TIMESTAMPTZ,
    completed_id    TEXT NOT NULL DEFAULT '',
    snapshot_recorded_at TIMESTAMPTZ,
    snapshot_id     TEXT NOT NULL DEFAULT '',
    retention_as_of TIMESTAMPTZ,
    source_cursor_recorded_at TIMESTAMPTZ,
    source_cursor_id TEXT NOT NULL DEFAULT '',
    staged_cursor_occurred_at TIMESTAMPTZ,
    staged_cursor_id TEXT NOT NULL DEFAULT '',
    policy_digest   TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, engagement_id),
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE,
    CHECK (watermark IS NULL OR max_observed_at IS NOT NULL),
    CHECK (watermark IS NULL OR watermark <= max_observed_at),
    CHECK ((phase = '' AND snapshot_recorded_at IS NULL AND retention_as_of IS NULL) OR (phase IN ('source','consume') AND snapshot_recorded_at IS NOT NULL AND snapshot_id <> '' AND retention_as_of IS NOT NULL AND policy_digest <> ''))
);
CALL synapse_enable_tenant_rls('correlation_checkpoints');

CREATE TABLE correlation_staged_signals (
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    snapshot_recorded_at TIMESTAMPTZ NOT NULL,
    snapshot_id TEXT NOT NULL,
    signal_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    asset_id TEXT NOT NULL,
    entity_id TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '' CHECK (severity IN ('', 'unknown', 'info', 'low', 'medium', 'high', 'critical')),
    rule_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    timeline JSONB,
    PRIMARY KEY (tenant_id, engagement_id, snapshot_recorded_at, snapshot_id, signal_id),
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES correlation_checkpoints(tenant_id, engagement_id) ON DELETE CASCADE
);
CREATE INDEX idx_correlation_staged_signals_consume ON correlation_staged_signals (tenant_id, engagement_id, snapshot_recorded_at, snapshot_id, occurred_at, signal_id COLLATE "C");
CALL synapse_enable_tenant_rls('correlation_staged_signals');

CREATE TABLE correlation_assignments (
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    signal_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    entity_id TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL,
    severity TEXT NOT NULL DEFAULT '' CHECK (severity IN ('', 'unknown', 'info', 'low', 'medium', 'high', 'critical')),
    outcome TEXT NOT NULL CHECK (outcome IN ('attached', 'suppressed', 'too_late')),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, engagement_id, signal_id),
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES correlation_checkpoints(tenant_id, engagement_id) ON DELETE CASCADE
);
CREATE INDEX idx_correlation_assignments_incident ON correlation_assignments (tenant_id, engagement_id, incident_id, occurred_at, signal_id COLLATE "C");
CALL synapse_enable_tenant_rls('correlation_assignments');

CREATE TABLE correlation_active_sessions (
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    entity_id TEXT NOT NULL DEFAULT '',
    incident_id TEXT NOT NULL,
    min_occurred_at TIMESTAMPTZ NOT NULL,
    max_occurred_at TIMESTAMPTZ NOT NULL,
    reflected_count INTEGER NOT NULL CHECK (reflected_count >= 0),
    max_severity TEXT NOT NULL DEFAULT '' CHECK (max_severity IN ('', 'unknown', 'info', 'low', 'medium', 'high', 'critical')),
    PRIMARY KEY (tenant_id, engagement_id, asset_id, entity_id, incident_id),
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES correlation_checkpoints(tenant_id, engagement_id) ON DELETE CASCADE,
    CHECK (min_occurred_at <= max_occurred_at)
);
CREATE INDEX idx_correlation_active_sessions_match ON correlation_active_sessions (tenant_id, engagement_id, asset_id, entity_id, max_occurred_at);
CALL synapse_enable_tenant_rls('correlation_active_sessions');
CREATE TRIGGER correlation_assignments_immutable BEFORE UPDATE OR DELETE ON correlation_assignments FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER correlation_assignments_no_truncate BEFORE TRUNCATE ON correlation_assignments FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
DROP TABLE correlation_active_sessions;
DROP TRIGGER IF EXISTS correlation_assignments_no_truncate ON correlation_assignments;
DROP TRIGGER IF EXISTS correlation_assignments_immutable ON correlation_assignments;
DROP TABLE correlation_assignments;
DROP TABLE correlation_staged_signals;
DROP TABLE correlation_checkpoints;
