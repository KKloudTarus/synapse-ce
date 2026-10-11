-- +goose Up
-- Channel template binding (EPIC #1327 WS2, #1371). A channel has one type, so it renders one
-- template family and binds at most one template: template_id names a tenant template of that
-- family, and resolution uses its active version before the tenant-wide templates. locale is the
-- language the channel renders in; NULL means the tenant's default locale.
--
-- A template is never deleted (0195: it is archived), so the foreign key cannot dangle; an archived
-- binding simply stops matching and resolution falls through. The binding is configuration, so it
-- is changed through the channel update and bumps the channel revision like any other edit.
ALTER TABLE notification_channels
    ADD COLUMN template_id TEXT CHECK (template_id IS NULL OR length(template_id) BETWEEN 1 AND 128),
    ADD COLUMN locale TEXT CHECK (locale IS NULL OR locale IN ('en', 'vi')),
    ADD CONSTRAINT notification_channels_template_fkey
        FOREIGN KEY (tenant_id, template_id) REFERENCES notification_templates(tenant_id, id);

CREATE INDEX notification_channels_template
    ON notification_channels (tenant_id, template_id) WHERE template_id IS NOT NULL;

-- The bound template must be of the channel's family. The API checks it first; this guard keeps a
-- direct write from binding, say, an email template to a Slack channel. A template's family never
-- changes (0195 head guard), so checking on the channel write is enough. The lookup runs under the
-- caller's tenant RLS, and the foreign key already confines the template to the channel's tenant.
-- +goose StatementBegin
CREATE FUNCTION notification_channel_template_family_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    bound_family TEXT;
    want_family  TEXT;
BEGIN
    IF NEW.template_id IS NULL THEN
        RETURN NEW;
    END IF;
    want_family := CASE NEW.channel_type
        WHEN 'webhook' THEN 'webhook'
        WHEN 'slack' THEN 'chat'
        WHEN 'email' THEN 'email'
    END;
    SELECT family INTO bound_family FROM notification_templates
        WHERE tenant_id = NEW.tenant_id AND id = NEW.template_id;
    IF bound_family IS NULL OR want_family IS NULL OR bound_family <> want_family THEN
        RAISE EXCEPTION 'notification channel template must be of the channel family' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_channels_template_family BEFORE INSERT OR UPDATE OF template_id, channel_type ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION notification_channel_template_family_guard();

-- +goose Down
DROP TRIGGER notification_channels_template_family ON notification_channels;
DROP FUNCTION notification_channel_template_family_guard();
DROP INDEX notification_channels_template;
ALTER TABLE notification_channels
    DROP CONSTRAINT notification_channels_template_fkey,
    DROP COLUMN locale,
    DROP COLUMN template_id;
