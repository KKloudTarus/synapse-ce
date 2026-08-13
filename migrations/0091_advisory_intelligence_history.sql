-- +goose Up
-- Global vulnerability-intelligence history. These tables are reference data shared by every tenant;
-- tenant-scoped occurrences, assessments, actions, and jobs are separate projections.
CREATE TABLE vulnerability_sync_runs (
    id                       TEXT PRIMARY KEY,
    source_id                TEXT NOT NULL REFERENCES vulnerability_sources(id),
    adapter_type             TEXT NOT NULL,
    mode                     TEXT NOT NULL CHECK (mode IN ('incremental', 'full')),
    trigger                  TEXT NOT NULL DEFAULT 'scheduled',
    client_idempotency_key   TEXT,
    durable_job_id           TEXT,
    checkpoint               JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(checkpoint) = 'object'),
    imported_count           BIGINT NOT NULL DEFAULT 0 CHECK (imported_count >= 0),
    skipped_count            BIGINT NOT NULL DEFAULT 0 CHECK (skipped_count >= 0),
    error_samples            JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(error_samples) = 'array'),
    state                    TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'partial')),
    started_at               TIMESTAMPTZ,
    finished_at              TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX vulnerability_sync_runs_active_source_mode
    ON vulnerability_sync_runs(source_id, mode) WHERE state IN ('queued', 'running');
CREATE UNIQUE INDEX vulnerability_sync_runs_idempotency_key
    ON vulnerability_sync_runs(source_id, client_idempotency_key) WHERE client_idempotency_key IS NOT NULL;
CREATE INDEX idx_vulnerability_sync_runs_source_freshness
    ON vulnerability_sync_runs(source_id, created_at DESC, id DESC);

CREATE TABLE advisory_observations (
    id                    TEXT PRIMARY KEY,
    source_id             TEXT NOT NULL REFERENCES vulnerability_sources(id),
    record_id             TEXT NOT NULL,
    identity_ids          TEXT[] NOT NULL,
    normalized_payload    JSONB NOT NULL CHECK (jsonb_typeof(normalized_payload) = 'object'),
    raw_payload           BYTEA,
    raw_reference         TEXT NOT NULL DEFAULT '',
    content_hash          TEXT NOT NULL,
    sync_run_id           TEXT REFERENCES vulnerability_sync_runs(id),
    is_current            BOOLEAN NOT NULL DEFAULT TRUE,
    observed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_id, record_id, content_hash)
);
CREATE UNIQUE INDEX advisory_observations_current_record
    ON advisory_observations(source_id, record_id) WHERE is_current;
CREATE INDEX idx_advisory_observations_identity
    ON advisory_observations USING GIN(identity_ids);
CREATE INDEX idx_advisory_observations_current
    ON advisory_observations(is_current, observed_at DESC);

CREATE TABLE advisory_aliases (
    alias_id       TEXT PRIMARY KEY,
    canonical_id   TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_advisory_aliases_canonical ON advisory_aliases(canonical_id);

CREATE TABLE advisory_revisions (
    advisory_id    TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    revision       BIGINT NOT NULL CHECK (revision > 0),
    content_hash   TEXT NOT NULL,
    data           JSONB NOT NULL CHECK (jsonb_typeof(data) = 'object'),
    changed_fields JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(changed_fields) = 'array'),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (advisory_id, revision)
);
CREATE INDEX idx_advisory_revisions_latest ON advisory_revisions(advisory_id, revision DESC);
CREATE INDEX idx_advisory_revisions_changed ON advisory_revisions(created_at DESC, advisory_id);
CREATE INDEX idx_advisory_revisions_hash ON advisory_revisions(advisory_id, content_hash);

-- +goose Down
DROP TABLE IF EXISTS advisory_revisions;
DROP TABLE IF EXISTS advisory_aliases;
DROP TABLE IF EXISTS advisory_observations;
DROP TABLE IF EXISTS vulnerability_sync_runs;
