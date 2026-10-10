-- +goose Up
-- EPIC #1327 WS4: personal delivery by Slack direct message (#1419) and Microsoft Teams personal
-- chat (#1420), tenant defaults for every personal channel (#1418), and rule recipient roles with
-- an engagement lead (#1415).

-- #1418: a person chooses in-app, email, Slack or Teams per event type.
ALTER TABLE user_notification_preferences DROP CONSTRAINT IF EXISTS user_notification_preferences_channel_check;
ALTER TABLE user_notification_preferences ADD CONSTRAINT user_notification_preferences_channel_check
    CHECK (channel IN ('in_app', 'email', 'slack', 'teams'));

-- #1418: what a person gets when they have not chosen. Precedence is mandatory > user choice >
-- this tenant default > the built-in default (in-app on, everything else off).
CREATE TABLE notification_personal_defaults (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    event_type TEXT NOT NULL CHECK (event_type ~ '^[a-z_]+(\.[a-z_]+)+$'),
    channel    TEXT NOT NULL CHECK (channel IN ('in_app', 'email', 'slack', 'teams')),
    enabled    BOOLEAN NOT NULL,
    revision   INT NOT NULL CHECK (revision >= 1),
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 200),
    PRIMARY KEY (tenant_id, event_type, channel)
);
CALL synapse_enable_tenant_rls('notification_personal_defaults');

-- #1415: a rule may address people by their relation to the event. Mention and approver roles are
-- refused until a producer records a verified identity.
ALTER TABLE notification_rules ADD COLUMN recipient_roles JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_recipient_roles_check CHECK (
    jsonb_typeof(recipient_roles) = 'array'
    AND recipient_roles <@ '["assignee", "team_member", "engagement_lead"]'::jsonb
);

-- #1415: the engagement lead is a same-tenant user, kept with the engagement's notification
-- settings. A setting row may now exist only for its lead, so the override keeps its default.
ALTER TABLE notification_engagement_settings ADD COLUMN lead_user_id TEXT;
ALTER TABLE notification_engagement_settings ADD CONSTRAINT notification_engagement_settings_lead_fk
    FOREIGN KEY (tenant_id, lead_user_id) REFERENCES users(ownership_tenant_id, id) ON DELETE SET NULL (lead_user_id);

-- #1419 and #1420: a Slack contact is <workspace>:<member> (T…:U…), never an email looked up in
-- Slack; a Teams contact is the person's Microsoft Entra object ID.
ALTER TABLE user_contacts ADD CONSTRAINT user_contacts_slack_value CHECK (
    kind <> 'slack' OR value ~ '^T[A-Z0-9]{2,30}:[UW][A-Z0-9]{2,30}$'
);
ALTER TABLE user_contacts ADD CONSTRAINT user_contacts_teams_value CHECK (
    kind <> 'teams' OR value ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
);

-- #1420: the bot's 1:1 conversation with a linked person. The reference (service URL and
-- conversation ID) is sealed; deleting the contact deletes it.
CREATE TABLE user_teams_conversations (
    tenant_id        TEXT NOT NULL,
    contact_id       TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    sealed_reference TEXT NOT NULL CHECK (btrim(sealed_reference) <> '' AND octet_length(sealed_reference) <= 8192),
    created_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, contact_id),
    FOREIGN KEY (tenant_id, user_id, contact_id) REFERENCES user_contacts(tenant_id, user_id, id) ON DELETE CASCADE
);
CALL synapse_enable_tenant_rls('user_teams_conversations');

-- #1420: a link code the Teams bot handed to someone who messaged it. The bot does not know the
-- tenant, so the offer is global and owner-only, like the inbound webhook registry (0199): the
-- runtime role reaches it only through the two SECURITY DEFINER functions below. A row holds the
-- digest of the code, a digest of the Teams conversation (for the per-conversation cap) and the
-- sealed conversation reference; it never holds a tenant or user.
CREATE TABLE teams_link_offers (
    code_digest      TEXT PRIMARY KEY CHECK (code_digest ~ '^[a-f0-9]{64}$'),
    conversation_key TEXT NOT NULL CHECK (conversation_key ~ '^[a-f0-9]{64}$'),
    sealed_reference TEXT NOT NULL CHECK (btrim(sealed_reference) <> '' AND octet_length(sealed_reference) <= 8192),
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '1 hour')
);
CREATE INDEX teams_link_offers_conversation ON teams_link_offers (conversation_key, created_at);
ALTER TABLE teams_link_offers ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams_link_offers FORCE ROW LEVEL SECURITY;
CREATE POLICY teams_link_offers_owner_all ON teams_link_offers
    FOR ALL TO PUBLIC
    USING (current_user = pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid='public.teams_link_offers'::regclass)))
    WITH CHECK (current_user = pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid='public.teams_link_offers'::regclass)));
REVOKE ALL ON TABLE teams_link_offers FROM PUBLIC;

-- Stores one offer. Expired offers are purged first; a conversation holds at most three live
-- offers, so someone messaging the bot repeatedly cannot fill the table. Returns false when the
-- cap refused the offer.
-- +goose StatementBegin
CREATE FUNCTION synapse_offer_teams_link(p_code_digest TEXT, p_conversation_key TEXT, p_sealed TEXT, p_expires_at TIMESTAMPTZ)
RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $teams_offer$
DECLARE
    live INT;
BEGIN
    DELETE FROM public.teams_link_offers WHERE expires_at <= now();
    PERFORM pg_advisory_xact_lock(hashtextextended('teams_link_offer:' || p_conversation_key, 0));
    SELECT count(*) INTO live FROM public.teams_link_offers WHERE conversation_key = p_conversation_key;
    IF live >= 3 THEN
        RETURN false;
    END IF;
    INSERT INTO public.teams_link_offers(code_digest, conversation_key, sealed_reference, expires_at)
    VALUES (p_code_digest, p_conversation_key, p_sealed, p_expires_at);
    RETURN true;
END;
$teams_offer$;
-- +goose StatementEnd

-- Claims one offer: returns its sealed reference and deletes it, so a code works once. An unknown
-- or expired code returns no row.
-- +goose StatementBegin
CREATE FUNCTION synapse_claim_teams_link(p_code_digest TEXT)
RETURNS TABLE(sealed_reference TEXT)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $teams_claim$
    DELETE FROM public.teams_link_offers o
    WHERE o.code_digest = p_code_digest AND o.expires_at > now()
    RETURNING o.sealed_reference
$teams_claim$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS synapse_claim_teams_link(TEXT);
DROP FUNCTION IF EXISTS synapse_offer_teams_link(TEXT, TEXT, TEXT, TIMESTAMPTZ);
DROP TABLE IF EXISTS teams_link_offers;
DROP TABLE IF EXISTS user_teams_conversations;
-- +goose StatementBegin
DO $$
BEGIN
    EXECUTE 'ALTER TABLE user_contacts NO FORCE ROW LEVEL SECURITY';
    DELETE FROM user_contacts WHERE kind IN ('slack', 'teams');
    EXECUTE 'ALTER TABLE user_contacts FORCE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE user_notification_preferences NO FORCE ROW LEVEL SECURITY';
    DELETE FROM user_notification_preferences WHERE channel IN ('slack', 'teams');
    EXECUTE 'ALTER TABLE user_notification_preferences FORCE ROW LEVEL SECURITY';
END $$;
-- +goose StatementEnd
ALTER TABLE user_contacts DROP CONSTRAINT IF EXISTS user_contacts_teams_value;
ALTER TABLE user_contacts DROP CONSTRAINT IF EXISTS user_contacts_slack_value;
ALTER TABLE notification_engagement_settings DROP CONSTRAINT IF EXISTS notification_engagement_settings_lead_fk;
ALTER TABLE notification_engagement_settings DROP COLUMN IF EXISTS lead_user_id;
ALTER TABLE notification_rules DROP CONSTRAINT IF EXISTS notification_rules_recipient_roles_check;
ALTER TABLE notification_rules DROP COLUMN IF EXISTS recipient_roles;
DROP TABLE IF EXISTS notification_personal_defaults;
ALTER TABLE user_notification_preferences DROP CONSTRAINT IF EXISTS user_notification_preferences_channel_check;
ALTER TABLE user_notification_preferences ADD CONSTRAINT user_notification_preferences_channel_check
    CHECK (channel IN ('in_app', 'email'));
