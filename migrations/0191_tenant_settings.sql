-- +goose Up
-- Tenant-wide presentation settings (#1359). Message templates and digests read the language and
-- the time zone from here. A tenant without a row uses the defaults ('en', 'UTC'), so nothing is
-- backfilled. The zone is stored as an IANA name, not an offset, so DST is resolved at render time;
-- the API validates it with time.LoadLocation and the CHECK only bounds its shape.
CREATE TABLE tenant_settings (
    tenant_id      TEXT PRIMARY KEY REFERENCES tenants(id),
    default_locale TEXT NOT NULL DEFAULT 'en' CHECK (default_locale IN ('en', 'vi')),
    time_zone      TEXT NOT NULL DEFAULT 'UTC' CHECK (time_zone ~ '^[A-Za-z0-9_+/-]{1,64}$' AND time_zone <> 'Local'),
    revision       INT NOT NULL CHECK (revision > 0),
    updated_at     TIMESTAMPTZ NOT NULL,
    updated_by     TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 200)
);
CALL synapse_enable_tenant_rls('tenant_settings');

-- +goose Down
DROP TABLE tenant_settings;
