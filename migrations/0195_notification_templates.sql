-- +goose Up
-- Tenant message templates (EPIC #1327 WS2, #1369). notification_templates is the mutable head of a
-- template: its key (event type or '*', channel family, locale or '*'), name, status and the two
-- version pointers. notification_template_versions holds the content, one immutable row per
-- version; a rollback activates an earlier version instead of rewriting one.
--
-- The CHECKs mirror internal/domain/notification/template.go and only bound shape. The API compiles
-- every field with internal/domain/msgtemplate before it saves a version.
CREATE TABLE notification_templates (
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    id             TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    name           TEXT NOT NULL CHECK (btrim(name) = name AND char_length(name) BETWEEN 1 AND 200),
    event_type     TEXT NOT NULL CHECK (event_type = '*' OR (event_type ~ '^[a-z_]+(\.[a-z_]+)+$' AND length(event_type) <= 128)),
    family         TEXT NOT NULL CHECK (family IN ('chat', 'email', 'pager', 'ticket', 'webhook')),
    locale         TEXT NOT NULL CHECK (locale IN ('en', 'vi', '*')),
    status         TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'archived')),
    -- latest_version is the newest version; active_version is the one that renders while the
    -- template is active and the last one that rendered once it is archived.
    latest_version INT NOT NULL CHECK (latest_version > 0),
    active_version INT CHECK (active_version > 0 AND active_version <= latest_version),
    revision       INT NOT NULL CHECK (revision > 0),
    created_at     TIMESTAMPTZ NOT NULL,
    created_by     TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200),
    updated_at     TIMESTAMPTZ NOT NULL,
    updated_by     TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 200),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT notification_templates_active_has_version CHECK (status <> 'active' OR active_version IS NOT NULL)
);

CREATE TABLE notification_template_versions (
    tenant_id   TEXT NOT NULL,
    template_id TEXT NOT NULL,
    version     INT NOT NULL CHECK (version > 0),
    -- One source string per content field of the family. Keys are field names, values are strings;
    -- the size cap is a backstop for the 16 KiB per-field limit the store enforces, allowing for
    -- JSON escaping.
    fields      JSONB NOT NULL CONSTRAINT notification_template_versions_fields_check CHECK (
        jsonb_typeof(fields) = 'object' AND fields <> '{}'::jsonb
        AND octet_length(fields::text) <= 262144
        AND NOT jsonb_path_exists(fields, 'strict $.keyvalue() ? (@.value.type() != "string" || !(@.key like_regex "^[a-z_]{1,32}$"))')
    ),
    checksum    TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    created_at  TIMESTAMPTZ NOT NULL,
    created_by  TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200),
    PRIMARY KEY (tenant_id, template_id, version),
    -- No cascade: a template with versions cannot be deleted, it is archived.
    FOREIGN KEY (tenant_id, template_id) REFERENCES notification_templates(tenant_id, id)
);

-- The active pointer must name a stored version of the same template.
ALTER TABLE notification_templates ADD CONSTRAINT notification_templates_active_version_fkey
    FOREIGN KEY (tenant_id, id, active_version) REFERENCES notification_template_versions(tenant_id, template_id, version);

-- At most one active template per key. Resolution (#1371) reads through this index.
CREATE UNIQUE INDEX notification_templates_one_active
    ON notification_templates (tenant_id, event_type, family, locale) WHERE status = 'active';

-- Versions are append-only, like the 0163 notification history: no row is updated or deleted.
-- +goose StatementBegin
CREATE FUNCTION notification_template_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'notification template versions are append-only' USING ERRCODE = '55000';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_template_versions_append_only BEFORE UPDATE OR DELETE ON notification_template_versions
    FOR EACH ROW EXECUTE FUNCTION notification_template_version_immutable();

-- A template's key and creation record never change, and its version counter only moves forward,
-- so a version always matches the key it was validated for.
-- +goose StatementBegin
CREATE FUNCTION notification_template_head_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.event_type IS DISTINCT FROM OLD.event_type OR NEW.family IS DISTINCT FROM OLD.family
       OR NEW.locale IS DISTINCT FROM OLD.locale
       OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
        RAISE EXCEPTION 'notification template key is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.latest_version < OLD.latest_version OR NEW.revision <= OLD.revision THEN
        RAISE EXCEPTION 'notification template version and revision only move forward' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_templates_head_guard BEFORE UPDATE ON notification_templates
    FOR EACH ROW EXECUTE FUNCTION notification_template_head_guard();

CALL synapse_enable_tenant_rls('notification_templates');
CALL synapse_enable_tenant_rls('notification_template_versions');

-- +goose Down
DROP TABLE notification_template_versions, notification_templates;
DROP FUNCTION notification_template_head_guard();
DROP FUNCTION notification_template_version_immutable();
