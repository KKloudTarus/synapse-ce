-- +goose Up
-- A3 (#697): common versioned Finding Identity and Observation lineage.

ALTER TABLE assessment_snapshots
    ADD CONSTRAINT assessment_snapshots_tenant_cycle_id_unique UNIQUE (tenant_id, cycle_id, id);

CREATE TABLE finding_identities (
    tenant_id                      TEXT NOT NULL,
    cycle_id                       TEXT NOT NULL,
    id                             TEXT NOT NULL,
    producer_kind                  TEXT NOT NULL CHECK (btrim(producer_kind) <> '' AND octet_length(producer_kind) <= 256),
    finding_kind                   TEXT NOT NULL CHECK (btrim(finding_kind) <> '' AND octet_length(finding_kind) <= 256),
    canonicalization_version       INTEGER NOT NULL CHECK (canonicalization_version = 1),
    fingerprint_schema_version     INTEGER NOT NULL CHECK (fingerprint_schema_version > 0),
    lineage_fingerprint            TEXT NOT NULL CHECK (lineage_fingerprint ~ '^[0-9a-f]{64}$'),
    target_identity_schema_version INTEGER NOT NULL CHECK (target_identity_schema_version > 0),
    target_identity_canonical      TEXT NOT NULL CHECK (btrim(target_identity_canonical) <> '' AND octet_length(target_identity_canonical) <= 2048),
    canonical_identity_fields      JSONB NOT NULL CHECK (jsonb_typeof(canonical_identity_fields) = 'object' AND octet_length(canonical_identity_fields::text) <= 32768),
    first_seen_snapshot_id         TEXT NOT NULL,
    created_at                     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, cycle_id, id),
    FOREIGN KEY (tenant_id, cycle_id) REFERENCES assessment_cycles(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, first_seen_snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, cycle_id, id) ON DELETE RESTRICT
);
CREATE INDEX idx_finding_identities_fingerprint ON finding_identities
    (tenant_id, cycle_id, producer_kind, finding_kind, target_identity_canonical, fingerprint_schema_version, lineage_fingerprint);

CREATE TABLE finding_identity_aliases (
    tenant_id        TEXT NOT NULL,
    cycle_id         TEXT NOT NULL,
    id               TEXT NOT NULL,
    identity_id      TEXT NOT NULL,
    producer_kind    TEXT NOT NULL CHECK (btrim(producer_kind) <> '' AND octet_length(producer_kind) <= 256),
    finding_kind     TEXT NOT NULL CHECK (btrim(finding_kind) <> '' AND octet_length(finding_kind) <= 256),
    target_canonical TEXT NOT NULL CHECK (btrim(target_canonical) <> '' AND octet_length(target_canonical) <= 2048),
    schema_version   INTEGER NOT NULL CHECK (schema_version > 0),
    fingerprint      TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    approved_by      TEXT NOT NULL CHECK (btrim(approved_by) <> '' AND octet_length(approved_by) <= 256),
    approved_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, cycle_id, id),
    UNIQUE (tenant_id, cycle_id, identity_id, producer_kind, finding_kind, target_canonical, schema_version, fingerprint),
    FOREIGN KEY (tenant_id, cycle_id, identity_id)
        REFERENCES finding_identities(tenant_id, cycle_id, id) ON DELETE RESTRICT
);
CREATE INDEX idx_finding_identity_aliases_lookup ON finding_identity_aliases
    (tenant_id, cycle_id, producer_kind, finding_kind, target_canonical, schema_version, fingerprint);

CREATE TABLE finding_observations (
    tenant_id           TEXT NOT NULL,
    cycle_id            TEXT NOT NULL,
    id                  TEXT NOT NULL,
    snapshot_id         TEXT NOT NULL,
    identity_id         TEXT NOT NULL,
    producer_kind       TEXT NOT NULL CHECK (btrim(producer_kind) <> '' AND octet_length(producer_kind) <= 256),
    finding_kind        TEXT NOT NULL CHECK (btrim(finding_kind) <> '' AND octet_length(finding_kind) <= 256),
    target_canonical    TEXT NOT NULL CHECK (btrim(target_canonical) <> '' AND octet_length(target_canonical) <= 2048),
    source_finding_id   TEXT NOT NULL DEFAULT '' CHECK (octet_length(source_finding_id) <= 512),
    source_occurrence_id TEXT NOT NULL DEFAULT '' CHECK (octet_length(source_occurrence_id) <= 512),
    severity            TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info','unknown')),
    risk_score_milli    INTEGER CHECK (risk_score_milli BETWEEN 0 AND 10000),
    component_version   TEXT NOT NULL DEFAULT '' CHECK (octet_length(component_version) <= 512),
    location            TEXT NOT NULL DEFAULT '' CHECK (octet_length(location) <= 512),
    reachability        TEXT NOT NULL DEFAULT '' CHECK (octet_length(reachability) <= 512),
    evidence_digest     TEXT NOT NULL DEFAULT '' CHECK (evidence_digest = '' OR evidence_digest ~ '^[0-9a-f]{64}$'),
    scanner_provenance  JSONB NOT NULL CHECK (jsonb_typeof(scanner_provenance) = 'object' AND octet_length(scanner_provenance::text) <= 4096),
    observed_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, cycle_id, id),
    UNIQUE (tenant_id, cycle_id, snapshot_id, producer_kind, finding_kind, target_canonical, source_finding_id, source_occurrence_id),
    FOREIGN KEY (tenant_id, cycle_id, snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, identity_id)
        REFERENCES finding_identities(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    CONSTRAINT finding_observations_source_check CHECK (source_finding_id <> '' OR source_occurrence_id <> '')
);
CREATE INDEX idx_finding_observations_snapshot ON finding_observations (tenant_id, cycle_id, snapshot_id, producer_kind, finding_kind);
CREATE INDEX idx_finding_observations_producer_id ON finding_observations
    (tenant_id, cycle_id, producer_kind, finding_kind, target_canonical, source_finding_id, identity_id);

CREATE TABLE finding_match_candidates (
    tenant_id                 TEXT NOT NULL,
    cycle_id                  TEXT NOT NULL,
    snapshot_id               TEXT NOT NULL,
    id                        TEXT NOT NULL,
    producer_kind             TEXT NOT NULL CHECK (btrim(producer_kind) <> '' AND octet_length(producer_kind) <= 256),
    finding_kind              TEXT NOT NULL CHECK (btrim(finding_kind) <> '' AND octet_length(finding_kind) <= 256),
    reason                    TEXT NOT NULL CHECK (reason IN ('fingerprint_collision','split','merge','insufficient_anchor','legacy_ambiguous')),
    fingerprint_schema_version INTEGER NOT NULL CHECK (fingerprint_schema_version >= 0),
    fingerprint               TEXT NOT NULL DEFAULT '' CHECK (fingerprint = '' OR fingerprint ~ '^[0-9a-f]{64}$'),
    source_reference_hash     TEXT NOT NULL CHECK (source_reference_hash ~ '^[0-9a-f]{64}$'),
    candidate_set_hash        TEXT NOT NULL CHECK (candidate_set_hash ~ '^[0-9a-f]{64}$'),
    status                    TEXT NOT NULL CHECK (status IN ('open','resolved','superseded')),
    version                   BIGINT NOT NULL CHECK (version > 0),
    created_at                TIMESTAMPTZ NOT NULL,
    resolved_at               TIMESTAMPTZ,
    superseded_at             TIMESTAMPTZ,
    superseded_by_candidate_id TEXT,
    PRIMARY KEY (tenant_id, cycle_id, id),
    UNIQUE (tenant_id, cycle_id, snapshot_id, producer_kind, reason, candidate_set_hash),
    FOREIGN KEY (tenant_id, cycle_id, snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, superseded_by_candidate_id)
        REFERENCES finding_match_candidates(tenant_id, cycle_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT finding_match_candidates_fingerprint_shape_check CHECK (
        (reason = 'insufficient_anchor' AND fingerprint_schema_version >= 0) OR
        (reason <> 'insufficient_anchor' AND fingerprint_schema_version > 0 AND fingerprint <> '')
    ),
    CONSTRAINT finding_match_candidates_status_metadata_check CHECK (
        (status = 'open' AND resolved_at IS NULL AND superseded_at IS NULL AND superseded_by_candidate_id IS NULL) OR
        (status = 'resolved' AND resolved_at IS NOT NULL AND superseded_at IS NULL AND superseded_by_candidate_id IS NULL) OR
        (status = 'superseded' AND resolved_at IS NULL AND superseded_at IS NOT NULL AND superseded_by_candidate_id IS NOT NULL)
    )
);
CREATE UNIQUE INDEX uq_finding_match_candidates_open_subject ON finding_match_candidates
    (tenant_id, cycle_id, snapshot_id, producer_kind, reason, source_reference_hash) WHERE status = 'open';
CREATE INDEX idx_finding_match_candidates_open_fingerprint ON finding_match_candidates
    (tenant_id, cycle_id, producer_kind, finding_kind, fingerprint_schema_version, fingerprint) WHERE status = 'open';

CREATE TABLE finding_match_candidate_refs (
    tenant_id               TEXT NOT NULL,
    cycle_id                TEXT NOT NULL,
    candidate_id            TEXT NOT NULL,
    position                INTEGER NOT NULL CHECK (position >= 0 AND position < 64),
    role                    TEXT NOT NULL CHECK (role IN ('source','candidate','selected','excluded')),
    identity_id             TEXT,
    observation_id          TEXT,
    external_reference_hash TEXT,
    match_method            TEXT NOT NULL CHECK (match_method IN ('override','producer_id','fingerprint','alias','matcher','manual','new_identity')),
    score_milli             INTEGER NOT NULL CHECK (score_milli BETWEEN 0 AND 1000),
    confidence              TEXT NOT NULL CHECK (confidence IN ('unknown','low','medium','high')),
    reason_payload          JSONB NOT NULL CHECK (jsonb_typeof(reason_payload) = 'object' AND octet_length(reason_payload::text) <= 4096),
    PRIMARY KEY (tenant_id, cycle_id, candidate_id, position),
    FOREIGN KEY (tenant_id, cycle_id, candidate_id)
        REFERENCES finding_match_candidates(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, identity_id)
        REFERENCES finding_identities(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, observation_id)
        REFERENCES finding_observations(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    CONSTRAINT finding_match_candidate_refs_subject_check CHECK (
        num_nonnulls(identity_id, observation_id, external_reference_hash) = 1 AND
        (external_reference_hash IS NULL OR external_reference_hash ~ '^[0-9a-f]{64}$')
    )
);

CREATE TABLE finding_match_resolution_events (
    tenant_id                  TEXT NOT NULL,
    cycle_id                   TEXT NOT NULL,
    candidate_id               TEXT NOT NULL,
    id                         TEXT NOT NULL,
    action                     TEXT NOT NULL CHECK (action IN ('confirm_existing','create_distinct_identity','unlink','dismiss','supersede')),
    actor                      TEXT NOT NULL CHECK (btrim(actor) <> '' AND octet_length(actor) <= 256),
    reason                     TEXT NOT NULL CHECK (btrim(reason) <> '' AND octet_length(reason) <= 2000),
    before_refs                JSONB NOT NULL CHECK (jsonb_typeof(before_refs) = 'array' AND octet_length(before_refs::text) <= 32768),
    after_refs                 JSONB NOT NULL CHECK (jsonb_typeof(after_refs) = 'array' AND octet_length(after_refs::text) <= 32768),
    successor_candidate_id     TEXT,
    expected_version           BIGINT NOT NULL CHECK (expected_version > 0),
    version                    BIGINT NOT NULL CHECK (version = expected_version + 1),
    prior_event_id             TEXT,
    content_hash               TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    created_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, cycle_id, id),
    UNIQUE (tenant_id, cycle_id, candidate_id, id),
    UNIQUE (tenant_id, cycle_id, candidate_id, version),
    FOREIGN KEY (tenant_id, cycle_id, candidate_id)
        REFERENCES finding_match_candidates(tenant_id, cycle_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, cycle_id, successor_candidate_id)
        REFERENCES finding_match_candidates(tenant_id, cycle_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, cycle_id, candidate_id, prior_event_id)
        REFERENCES finding_match_resolution_events(tenant_id, cycle_id, candidate_id, id) ON DELETE RESTRICT,
    CONSTRAINT finding_match_resolution_events_prior_check CHECK (
        (expected_version = 1 AND prior_event_id IS NULL) OR expected_version > 1
    ),
    CONSTRAINT finding_match_resolution_events_successor_check CHECK (
        (action = 'supersede' AND successor_candidate_id IS NOT NULL) OR
        (action <> 'supersede' AND successor_candidate_id IS NULL)
    )
);

CREATE TABLE finding_match_override_events (
    tenant_id             TEXT NOT NULL,
    cycle_id              TEXT NOT NULL,
    id                    TEXT NOT NULL,
    action                TEXT NOT NULL CHECK (action IN ('confirm','unlink','supersede')),
    source_observation_id TEXT NOT NULL,
    source_identity_id    TEXT,
    target_observation_id TEXT,
    target_identity_id    TEXT NOT NULL,
    actor                 TEXT NOT NULL CHECK (btrim(actor) <> '' AND octet_length(actor) <= 256),
    reason                TEXT NOT NULL CHECK (btrim(reason) <> '' AND octet_length(reason) <= 2000),
    expected_version      BIGINT NOT NULL CHECK (expected_version >= 0),
    version               BIGINT NOT NULL CHECK (version = expected_version + 1),
    prior_event_id        TEXT,
    content_hash          TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    created_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, cycle_id, id),
    UNIQUE (tenant_id, cycle_id, source_observation_id, id),
    UNIQUE (tenant_id, cycle_id, source_observation_id, version),
    FOREIGN KEY (tenant_id, cycle_id, source_observation_id)
        REFERENCES finding_observations(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, source_identity_id)
        REFERENCES finding_identities(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, target_observation_id)
        REFERENCES finding_observations(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, target_identity_id)
        REFERENCES finding_identities(tenant_id, cycle_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, cycle_id, source_observation_id, prior_event_id)
        REFERENCES finding_match_override_events(tenant_id, cycle_id, source_observation_id, id) ON DELETE RESTRICT,
    CONSTRAINT finding_match_override_events_prior_check CHECK (
        (expected_version = 0 AND prior_event_id IS NULL) OR
        (expected_version > 0 AND prior_event_id IS NOT NULL)
    )
);

CREATE TABLE finding_lineage_skip_records (
    tenant_id            TEXT NOT NULL,
    cycle_id             TEXT NOT NULL,
    snapshot_id          TEXT NOT NULL,
    id                   TEXT NOT NULL,
    producer_kind        TEXT NOT NULL CHECK (btrim(producer_kind) <> '' AND octet_length(producer_kind) <= 256),
    finding_kind         TEXT NOT NULL CHECK (btrim(finding_kind) <> '' AND octet_length(finding_kind) <= 256),
    reason               TEXT NOT NULL CHECK (reason IN ('invalid_trust','invalid_ownership','redaction_required')),
    source_reference_hash TEXT NOT NULL CHECK (source_reference_hash ~ '^[0-9a-f]{64}$'),
    detail_code          TEXT NOT NULL CHECK (btrim(detail_code) <> '' AND octet_length(detail_code) <= 256),
    created_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, cycle_id, id),
    UNIQUE (tenant_id, cycle_id, snapshot_id, producer_kind, reason, source_reference_hash),
    FOREIGN KEY (tenant_id, cycle_id, snapshot_id)
        REFERENCES assessment_snapshots(tenant_id, cycle_id, id) ON DELETE RESTRICT
);

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_finding_match_candidate_update() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'finding match candidates cannot be deleted';
    END IF;
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.cycle_id IS DISTINCT FROM NEW.cycle_id
        OR OLD.snapshot_id IS DISTINCT FROM NEW.snapshot_id
        OR OLD.id IS DISTINCT FROM NEW.id
        OR OLD.producer_kind IS DISTINCT FROM NEW.producer_kind
        OR OLD.finding_kind IS DISTINCT FROM NEW.finding_kind
        OR OLD.reason IS DISTINCT FROM NEW.reason
        OR OLD.fingerprint_schema_version IS DISTINCT FROM NEW.fingerprint_schema_version
        OR OLD.fingerprint IS DISTINCT FROM NEW.fingerprint
        OR OLD.source_reference_hash IS DISTINCT FROM NEW.source_reference_hash
        OR OLD.candidate_set_hash IS DISTINCT FROM NEW.candidate_set_hash
        OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'finding match candidate immutable fields cannot change';
    END IF;
    IF OLD.status <> 'open' OR NEW.status NOT IN ('resolved','superseded') OR NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'finding match candidate requires one open-to-terminal CAS transition';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER finding_match_candidates_guard
    BEFORE UPDATE OR DELETE ON finding_match_candidates
    FOR EACH ROW EXECUTE FUNCTION synapse_guard_finding_match_candidate_update();
CREATE TRIGGER finding_match_candidates_no_truncate
    BEFORE TRUNCATE ON finding_match_candidates
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

CREATE TRIGGER finding_identities_append_only BEFORE UPDATE OR DELETE ON finding_identities FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_identities_no_truncate BEFORE TRUNCATE ON finding_identities FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_identity_aliases_append_only BEFORE UPDATE OR DELETE ON finding_identity_aliases FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_identity_aliases_no_truncate BEFORE TRUNCATE ON finding_identity_aliases FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_observations_append_only BEFORE UPDATE OR DELETE ON finding_observations FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_observations_no_truncate BEFORE TRUNCATE ON finding_observations FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_match_candidate_refs_append_only BEFORE UPDATE OR DELETE ON finding_match_candidate_refs FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_match_candidate_refs_no_truncate BEFORE TRUNCATE ON finding_match_candidate_refs FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_match_resolution_events_append_only BEFORE UPDATE OR DELETE ON finding_match_resolution_events FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_match_resolution_events_no_truncate BEFORE TRUNCATE ON finding_match_resolution_events FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_match_override_events_append_only BEFORE UPDATE OR DELETE ON finding_match_override_events FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_match_override_events_no_truncate BEFORE TRUNCATE ON finding_match_override_events FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_lineage_skip_records_append_only BEFORE UPDATE OR DELETE ON finding_lineage_skip_records FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER finding_lineage_skip_records_no_truncate BEFORE TRUNCATE ON finding_lineage_skip_records FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

CALL synapse_enable_tenant_rls('finding_identities');
CALL synapse_enable_tenant_rls('finding_identity_aliases');
CALL synapse_enable_tenant_rls('finding_observations');
CALL synapse_enable_tenant_rls('finding_match_candidates');
CALL synapse_enable_tenant_rls('finding_match_candidate_refs');
CALL synapse_enable_tenant_rls('finding_match_resolution_events');
CALL synapse_enable_tenant_rls('finding_match_override_events');
CALL synapse_enable_tenant_rls('finding_lineage_skip_records');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM finding_identities)
        OR EXISTS (SELECT 1 FROM finding_identity_aliases)
        OR EXISTS (SELECT 1 FROM finding_observations)
        OR EXISTS (SELECT 1 FROM finding_match_candidates)
        OR EXISTS (SELECT 1 FROM finding_match_candidate_refs)
        OR EXISTS (SELECT 1 FROM finding_match_resolution_events)
        OR EXISTS (SELECT 1 FROM finding_match_override_events)
        OR EXISTS (SELECT 1 FROM finding_lineage_skip_records) THEN
        RAISE EXCEPTION 'cannot roll back finding lineage while lineage rows exist';
    END IF;
END $$;
-- +goose StatementEnd

DROP TABLE finding_match_override_events;
DROP TABLE finding_match_resolution_events;
DROP TABLE finding_match_candidate_refs;
DROP TRIGGER IF EXISTS finding_match_candidates_no_truncate ON finding_match_candidates;
DROP TRIGGER IF EXISTS finding_match_candidates_guard ON finding_match_candidates;
DROP FUNCTION IF EXISTS synapse_guard_finding_match_candidate_update();
DROP TABLE finding_match_candidates;
DROP TABLE finding_lineage_skip_records;
DROP TABLE finding_observations;
DROP TABLE finding_identity_aliases;
DROP TABLE finding_identities;
ALTER TABLE assessment_snapshots DROP CONSTRAINT assessment_snapshots_tenant_cycle_id_unique;
