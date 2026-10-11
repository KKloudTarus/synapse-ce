-- +goose Up
-- Custom JSON body for generic webhooks (EPIC #1327, #1376). custom_body opts a webhook channel into
-- sending the body of its webhook template instead of the event envelope; the request then carries
-- X-Synapse-Body: custom and the signature covers the body as sent. It needs a bound template
-- (0200), so the opt-in always names one template, and it exists only on webhook channels.
ALTER TABLE notification_channels
    ADD COLUMN custom_body BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT notification_channels_custom_body_check
        CHECK (NOT custom_body OR (template_id IS NOT NULL AND channel_type = 'webhook'));

-- +goose Down
ALTER TABLE notification_channels
    DROP CONSTRAINT notification_channels_custom_body_check,
    DROP COLUMN custom_body;
