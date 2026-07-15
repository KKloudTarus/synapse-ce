-- +goose Up
CREATE TABLE projects (
    id                      TEXT PRIMARY KEY,
    tenant_id               TEXT NOT NULL REFERENCES tenants(id),
    name                    TEXT NOT NULL,
    key                     TEXT NOT NULL,
    source_binding          JSONB NOT NULL,
    default_profile_by_lang JSONB NOT NULL DEFAULT '{}',
    gate_id                 TEXT NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by              TEXT NOT NULL DEFAULT '',
    updated_by              TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, key)
);
CREATE INDEX idx_projects_tenant_created ON projects(tenant_id, created_at DESC);

-- +goose Down
DROP TABLE projects;
