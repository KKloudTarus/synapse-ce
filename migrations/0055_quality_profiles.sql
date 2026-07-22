-- +goose Up
CREATE TABLE quality_profiles (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    key             TEXT NOT NULL,
    name            TEXT NOT NULL,
    language        TEXT NOT NULL,
    parent          TEXT NOT NULL DEFAULT '',
    activated_rules JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key)
);

CREATE INDEX idx_quality_profiles_tenant_language ON quality_profiles (tenant_id, language);

-- +goose Down
DROP TABLE quality_profiles;
