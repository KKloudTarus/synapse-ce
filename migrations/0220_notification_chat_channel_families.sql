-- +goose Up
-- EPIC #1327 WS3 (#1378 to #1381). Microsoft Teams, Telegram, Google Chat and Discord channels
-- render the chat template family, like Slack. The channel_type column has accepted any
-- well-formed type since 0190, but the 0200 family guard maps only webhook, slack and email, so a
-- chat template bound to one of the new channel types would be refused. The guard now maps every
-- chat type; it still refuses a type it does not know, so a future type has to be added here too.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notification_channel_template_family_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
        WHEN 'teams' THEN 'chat'
        WHEN 'telegram' THEN 'chat'
        WHEN 'google_chat' THEN 'chat'
        WHEN 'discord' THEN 'chat'
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

-- +goose Down
-- Restores the 0200 guard. A chat channel of a new type that has a bound template keeps it; only
-- a later write to that channel's binding is refused again.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notification_channel_template_family_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
