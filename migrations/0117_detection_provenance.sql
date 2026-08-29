-- +goose Up
-- #610 durable detection provenance. The current table is an operational read projection; every
-- state change is additionally recorded in the append-only transition history. Evidence content
-- is never updated when telemetry durability changes.
CREATE TABLE detection_provenance_current (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    detection_id  TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('pending', 'complete', 'expired', 'broken')),
    evidence_id   TEXT,
    pending_input BYTEA NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, engagement_id, detection_id)
);
CREATE INDEX idx_detection_provenance_current_engagement
    ON detection_provenance_current (tenant_id, engagement_id, updated_at);
CALL synapse_enable_tenant_rls('detection_provenance_current');

CREATE TABLE detection_provenance_transitions (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    detection_id  TEXT NOT NULL,
    sequence      BIGINT NOT NULL CHECK (sequence >= 1),
    kind          TEXT NOT NULL CHECK (kind IN ('received', 'telemetry_durable', 'commitment_pending', 'commitment_sealed', 'acknowledged', 'expired', 'broken')),
    status        TEXT NOT NULL CHECK (status IN ('pending', 'complete', 'expired', 'broken')),
    evidence_id   TEXT,
    agent_id      TEXT,
    asset_id      TEXT,
    telemetry_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    reason        TEXT NOT NULL DEFAULT '',
    previous_hash TEXT NOT NULL DEFAULT '',
    entry_hash    TEXT NOT NULL CHECK (entry_hash <> ''),
    occurred_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, engagement_id, detection_id, sequence)
);
CREATE INDEX idx_detection_provenance_transitions_engagement
    ON detection_provenance_transitions (tenant_id, engagement_id, detection_id, sequence);
CREATE UNIQUE INDEX detection_provenance_chain_link_uniq
    ON detection_provenance_transitions (tenant_id, engagement_id, detection_id, previous_hash);
CALL synapse_enable_tenant_rls('detection_provenance_transitions');

-- The history is a fact log. Application code only inserts; this trigger also rejects accidental
-- UPDATE/DELETE/TRUNCATE through a future repository path.
CREATE TRIGGER detection_provenance_transitions_append_only
    BEFORE UPDATE OR DELETE ON detection_provenance_transitions
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER detection_provenance_transitions_no_truncate
    BEFORE TRUNCATE ON detection_provenance_transitions
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM detection_provenance_current LIMIT 1)
       OR EXISTS (SELECT 1 FROM detection_provenance_transitions LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back 0117: detection provenance exists';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS detection_provenance_transitions_no_truncate ON detection_provenance_transitions;
DROP TRIGGER IF EXISTS detection_provenance_transitions_append_only ON detection_provenance_transitions;
DROP TABLE detection_provenance_transitions;
DROP TABLE detection_provenance_current;
