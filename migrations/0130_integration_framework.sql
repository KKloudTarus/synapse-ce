-- +goose Up
CREATE TABLE integrations (
    id                     TEXT PRIMARY KEY,
    tenant_id              TEXT NOT NULL REFERENCES tenants(id),
    provider               TEXT NOT NULL,
    display_name           TEXT NOT NULL,
    endpoint               TEXT NOT NULL,
    config                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    allow_private_network  BOOLEAN NOT NULL DEFAULT FALSE,
    poll_interval_seconds  BIGINT NOT NULL DEFAULT 300,
    enabled                BOOLEAN NOT NULL DEFAULT FALSE,
    archived               BOOLEAN NOT NULL DEFAULT FALSE,
    version                INT NOT NULL DEFAULT 1,
	connection_revision    INT NOT NULL DEFAULT 1,
	credential_revision    INT NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    CONSTRAINT integrations_tenant_id_id_unique UNIQUE (tenant_id, id),
    CONSTRAINT integrations_provider_nonempty CHECK (provider <> ''),
    CONSTRAINT integrations_name_nonempty CHECK (display_name <> ''),
    CONSTRAINT integrations_config_object CHECK (jsonb_typeof(config) = 'object' AND octet_length(config::text) <= 32768),
    CONSTRAINT integrations_poll_interval_bounds CHECK (poll_interval_seconds BETWEEN 30 AND 86400),
	CONSTRAINT integrations_version_positive CHECK (version > 0),
	CONSTRAINT integrations_revision_positive CHECK (connection_revision > 0 AND credential_revision >= 0)
);
CREATE UNIQUE INDEX integrations_active_endpoint_unique
    ON integrations (tenant_id, provider, endpoint) WHERE archived = FALSE;
CREATE INDEX integrations_tenant_state_idx
    ON integrations (tenant_id, enabled, archived, updated_at);
CALL synapse_enable_tenant_rls('integrations');

CREATE TABLE integration_credentials (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    integration_id  TEXT NOT NULL,
    credential_id   TEXT NOT NULL,
    ciphertext      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, integration_id, credential_id),
    CONSTRAINT integration_credentials_integration_fk FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT integration_credentials_ciphertext_bounded CHECK (ciphertext <> '' AND octet_length(ciphertext) <= 65536)
);
CREATE INDEX integration_credentials_integration_idx
    ON integration_credentials (tenant_id, integration_id);
CALL synapse_enable_tenant_rls('integration_credentials');

CREATE TABLE integration_bindings (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    integration_id  TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    external_key    TEXT NOT NULL,
    external_name   TEXT NOT NULL,
    version         INT NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT integration_bindings_tenant_id_id_unique UNIQUE (tenant_id, id),
    CONSTRAINT integration_bindings_integration_fk FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT integration_bindings_project_fk FOREIGN KEY (tenant_id, project_id)
        REFERENCES projects(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT integration_bindings_external_key_nonempty CHECK (external_key <> '' AND octet_length(external_key) <= 1024),
    CONSTRAINT integration_bindings_external_name_nonempty CHECK (external_name <> '' AND octet_length(external_name) <= 1024),
    CONSTRAINT integration_bindings_version_positive CHECK (version > 0),
    CONSTRAINT integration_bindings_external_unique UNIQUE (tenant_id, integration_id, external_key)
);
CREATE INDEX integration_bindings_project_idx
    ON integration_bindings (tenant_id, project_id);
CREATE INDEX integration_bindings_integration_idx
    ON integration_bindings (tenant_id, integration_id);
CALL synapse_enable_tenant_rls('integration_bindings');

CREATE TABLE integration_operations (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    integration_id  TEXT NOT NULL,
    operation_type  TEXT NOT NULL,
    state           TEXT NOT NULL,
    checkpoint      TEXT NOT NULL DEFAULT '',
    counts          JSONB NOT NULL DEFAULT '{}'::jsonb,
    errors          JSONB NOT NULL DEFAULT '[]'::jsonb,
    pipelines       JSONB NOT NULL DEFAULT '[]'::jsonb,
    job_id          TEXT NOT NULL UNIQUE REFERENCES jobs(id),
    actor           TEXT NOT NULL,
	connection_revision INT NOT NULL,
	credential_revision INT NOT NULL,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT integration_operations_tenant_id_id_unique UNIQUE (tenant_id, id),
    CONSTRAINT integration_operations_integration_fk FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT integration_operations_type_check CHECK (operation_type IN ('test','discover','poll')),
    CONSTRAINT integration_operations_state_check CHECK (state IN ('queued','running','succeeded','partial','failed','cancelled')),
	CONSTRAINT integration_operations_revision_check CHECK (connection_revision > 0 AND credential_revision >= 0),
    CONSTRAINT integration_operations_checkpoint_bounded CHECK (octet_length(checkpoint) <= 65536),
    CONSTRAINT integration_operations_counts_bounded CHECK (jsonb_typeof(counts) = 'object' AND octet_length(counts::text) <= 16384),
    CONSTRAINT integration_operations_errors_bounded CHECK (jsonb_typeof(errors) = 'array' AND octet_length(errors::text) <= 16384),
    CONSTRAINT integration_operations_pipelines_bounded CHECK (jsonb_typeof(pipelines) = 'array' AND octet_length(pipelines::text) <= 1048576)
);
CREATE UNIQUE INDEX integration_operations_one_active_idx
    ON integration_operations (tenant_id, integration_id) WHERE state IN ('queued','running');
CREATE INDEX integration_operations_history_idx
    ON integration_operations (tenant_id, integration_id, created_at DESC, id DESC);
CALL synapse_enable_tenant_rls('integration_operations');

CREATE TABLE integration_external_runs (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id),
    integration_id       TEXT NOT NULL,
    binding_id           TEXT,
    provider_key         TEXT NOT NULL,
    pipeline_key         TEXT NOT NULL,
    run_number           TEXT NOT NULL DEFAULT '',
    run_url              TEXT NOT NULL DEFAULT '',
    lifecycle            TEXT NOT NULL,
    result               TEXT NOT NULL,
    revision             TEXT NOT NULL DEFAULT '',
    branch               TEXT NOT NULL DEFAULT '',
    analysis_id          TEXT REFERENCES project_analyses(id) ON DELETE SET NULL,
    correlation          TEXT NOT NULL,
    queued_at            TIMESTAMPTZ,
    started_at           TIMESTAMPTZ,
    finished_at          TIMESTAMPTZ,
    provider_updated_at  TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL,
    CONSTRAINT integration_external_runs_integration_fk FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT integration_external_runs_binding_fk FOREIGN KEY (tenant_id, binding_id)
        REFERENCES integration_bindings(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT integration_external_runs_provider_key_bounded CHECK (provider_key <> '' AND octet_length(provider_key) <= 1024),
    CONSTRAINT integration_external_runs_pipeline_key_bounded CHECK (pipeline_key <> '' AND octet_length(pipeline_key) <= 1024),
    CONSTRAINT integration_external_runs_lifecycle_check CHECK (lifecycle IN ('queued','running','completed')),
    CONSTRAINT integration_external_runs_result_check CHECK (result IN ('success','failure','unstable','aborted','not_built','unknown')),
    CONSTRAINT integration_external_runs_correlation_check CHECK (correlation IN ('linked','missing','ambiguous')),
    CONSTRAINT integration_external_runs_provider_unique UNIQUE (tenant_id, integration_id, provider_key)
);
CREATE INDEX integration_external_runs_recent_idx
    ON integration_external_runs (tenant_id, integration_id, provider_updated_at DESC, id DESC);
CREATE INDEX integration_external_runs_binding_idx
    ON integration_external_runs (tenant_id, binding_id);
CREATE INDEX integration_external_runs_analysis_idx
    ON integration_external_runs (tenant_id, analysis_id) WHERE analysis_id IS NOT NULL;
CALL synapse_enable_tenant_rls('integration_external_runs');

-- +goose Down
DROP TABLE integration_external_runs;
DROP TABLE integration_operations;
DROP TABLE integration_bindings;
DROP TABLE integration_credentials;
DROP TABLE integrations;
