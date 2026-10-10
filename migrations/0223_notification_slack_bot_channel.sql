-- +goose Up
-- EPIC #1327 WS3 (#1383). Slack bot channels (channel_type 'slack_bot') post with chat.postMessage
-- and render the chat template family, like the incoming-webhook Slack channel. The channel_type
-- column accepts any well-formed type since 0190; the family guard from 0220 maps only the types it
-- knows, so it now maps slack_bot too.
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
        WHEN 'slack_bot' THEN 'chat'
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
-- Restores the 0220 guard. A Slack bot channel that has a bound template keeps it; only a later
-- write to that channel's binding is refused again.
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
