-- +goose Up
-- EPIC #1327 N03. New event and channel types are catalog and registry entries in code, not schema
-- changes: the enum CHECKs from 0163 and 0169 become shape checks. The columns later issues need
-- (subject keys, template context snapshots, template and remote references) are added now, in one
-- migration, so those issues ship without touching the schema.
--
-- Every new column has a constant default, so no table is rewritten and the append-only guards on
-- notification_events and notification_delivery_attempts do not fire. Constraints keep the names
-- PostgreSQL gave the 0163 inline checks, so Down can restore the enum lists exactly.

ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_channel_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_channel_type_check
    CHECK (channel_type ~ '^[a-z_]+$');

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_channel_type_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_channel_type_check
    CHECK (channel_type ~ '^[a-z_]+$');

ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_event_type_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_event_type_check
    CHECK (event_type ~ '^[a-z_]+(\.[a-z_]+)+$');

-- A newer envelope version is valid; the code that reads an event decides what it understands.
ALTER TABLE notification_events DROP CONSTRAINT notification_events_schema_version_check;
ALTER TABLE notification_events ADD CONSTRAINT notification_events_schema_version_check
    CHECK (schema_version >= 1);

-- Subject keys (EPIC D8) name the entity an event is about, for example an incident, apart from
-- the source key used for idempotency. context is the template context snapshot taken at
-- projection (EPIC D5); its size cap is a backstop, the builders bound it far lower.
ALTER TABLE notification_source_records
    ADD COLUMN schema_version INT NOT NULL DEFAULT 1 CONSTRAINT notification_source_records_schema_version_check CHECK (schema_version >= 1),
    ADD COLUMN subject_kind TEXT NOT NULL DEFAULT '' CONSTRAINT notification_source_records_subject_kind_check CHECK (subject_kind ~ '^([a-z_]+)?$'),
    ADD COLUMN subject_id TEXT NOT NULL DEFAULT '' CONSTRAINT notification_source_records_subject_id_check CHECK (length(subject_id) <= 512),
    ADD COLUMN context JSONB NOT NULL DEFAULT '{}'::jsonb CONSTRAINT notification_source_records_context_check
        CHECK (jsonb_typeof(context) = 'object' AND octet_length(context::text) <= 1048576);

ALTER TABLE notification_events
    ADD COLUMN subject_kind TEXT NOT NULL DEFAULT '' CONSTRAINT notification_events_subject_kind_check CHECK (subject_kind ~ '^([a-z_]+)?$'),
    ADD COLUMN subject_id TEXT NOT NULL DEFAULT '' CONSTRAINT notification_events_subject_id_check CHECK (length(subject_id) <= 512),
    ADD COLUMN context JSONB NOT NULL DEFAULT '{}'::jsonb CONSTRAINT notification_events_context_check
        CHECK (jsonb_typeof(context) = 'object' AND octet_length(context::text) <= 1048576);

-- remote_ref is the provider's handle for a delivered message (a Slack ts, a ticket key), used to
-- thread replies (EPIC D8). template_ref pins the resolved template on the first attempt so
-- retries render the same text; each attempt records the one it used, written when the attempt
-- starts, so the 0163 finalize guard does not need to change.
ALTER TABLE notification_deliveries
    ADD COLUMN remote_ref TEXT NOT NULL DEFAULT '' CONSTRAINT notification_deliveries_remote_ref_check CHECK (length(remote_ref) <= 512),
    ADD COLUMN template_ref TEXT NOT NULL DEFAULT '' CONSTRAINT notification_deliveries_template_ref_check CHECK (length(template_ref) <= 256);

ALTER TABLE notification_delivery_attempts
    ADD COLUMN template_ref TEXT NOT NULL DEFAULT '' CONSTRAINT notification_delivery_attempts_template_ref_check CHECK (length(template_ref) <= 256);

-- +goose Down
-- Restoring the enum lists fails if rows with a newer type exist. That is deliberate: delete or
-- migrate them explicitly before rolling back, rather than lose them silently.
ALTER TABLE notification_delivery_attempts DROP COLUMN template_ref;
ALTER TABLE notification_deliveries DROP COLUMN template_ref, DROP COLUMN remote_ref;
ALTER TABLE notification_events DROP COLUMN context, DROP COLUMN subject_id, DROP COLUMN subject_kind;
ALTER TABLE notification_source_records DROP COLUMN context, DROP COLUMN subject_id, DROP COLUMN subject_kind, DROP COLUMN schema_version;

ALTER TABLE notification_events DROP CONSTRAINT notification_events_schema_version_check;
ALTER TABLE notification_events ADD CONSTRAINT notification_events_schema_version_check
    CHECK (schema_version = 1);

ALTER TABLE notification_rules DROP CONSTRAINT notification_rules_event_type_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_event_type_check
    CHECK (event_type IN ('vulnerability_action.created','scan.completed','quality_gate.failed',
    'sla.approaching_deadline','fleet.agent.offline','incident.created','finding.ownership_changed'));

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_channel_type_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_channel_type_check
    CHECK (channel_type IN ('webhook','slack','email'));

ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_channel_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_channel_type_check
    CHECK (channel_type IN ('webhook','slack','email'));
