-- +goose Up
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
        WHEN 'mattermost' THEN 'chat'
        WHEN 'rocket_chat' THEN 'chat'
        WHEN 'pagerduty' THEN 'pager'
        WHEN 'jsm' THEN 'pager'
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
-- The forward guard preserves the previously migrated slack_bot mapping. Its down step
-- also retains that mapping: rolling back these channel families must not make a Slack bot
-- channel fail an unrelated template update.
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
