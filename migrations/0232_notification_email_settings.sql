-- +goose Up
-- A tenant relay is distinct from an email channel: channels only carry their
-- recipients, while this row carries one sealed relay configuration revision.
CREATE TABLE notification_email_settings (
 tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
 revision INT NOT NULL CHECK (revision > 0),
 configured BOOLEAN NOT NULL DEFAULT false,
 host TEXT NOT NULL DEFAULT '' CHECK (NOT configured OR length(host) BETWEEN 1 AND 253),
 port INT NOT NULL DEFAULT 0 CHECK (NOT configured OR port IN (465,587)),
 sender TEXT NOT NULL DEFAULT '' CHECK (NOT configured OR length(sender) BETWEEN 3 AND 320),
 auth_mode TEXT NOT NULL DEFAULT 'none' CHECK (auth_mode IN ('none','password','google_oauth','microsoft_oauth')),
 sealed TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL,
 updated_by TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 200)
);
CALL synapse_enable_tenant_rls('notification_email_settings');

CREATE TABLE notification_email_domains (
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 domain TEXT NOT NULL CHECK (length(domain) BETWEEN 1 AND 253),
 created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (tenant_id,domain)
);
CALL synapse_enable_tenant_rls('notification_email_domains');

CREATE INDEX idx_notification_verified_email_recipients
ON user_contacts(tenant_id,value,user_id)
WHERE kind='email' AND verified_at IS NOT NULL;

-- +goose Down
DROP INDEX idx_notification_verified_email_recipients;
DROP TABLE notification_email_domains;
DROP TABLE notification_email_settings;
