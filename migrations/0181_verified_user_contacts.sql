-- +goose Up
-- WS4 U01: self-managed contact identities. An address is never authoritative
-- until verification succeeds. Only the owner may see the contact API projection.
CREATE TABLE user_contacts (
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK (kind IN ('email','slack','teams')),
 value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 320),
 source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','oidc')),
 source_key TEXT,
 verified_at TIMESTAMPTZ,
 version INT NOT NULL DEFAULT 1 CHECK (version > 0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id,id),
 UNIQUE (tenant_id,user_id,id),
 FOREIGN KEY (tenant_id,user_id) REFERENCES users(ownership_tenant_id,id),
 CHECK ((source='manual' AND source_key IS NULL) OR (source='oidc' AND kind='email' AND source_key IS NOT NULL))
);
CALL synapse_enable_tenant_rls('user_contacts');
CREATE INDEX user_contacts_owner ON user_contacts(tenant_id,user_id,kind,created_at DESC);
CREATE UNIQUE INDEX user_contacts_manual_value ON user_contacts(tenant_id,user_id,kind,value) WHERE source='manual';
CREATE UNIQUE INDEX user_contacts_oidc_source ON user_contacts(tenant_id,user_id,source_key) WHERE source='oidc';

-- A challenge is bound to the exact contact version and destination. A worker
-- receives only the challenge ID; the code is sealed with tenant-scoped AAD.
CREATE TABLE user_contact_challenges (
 tenant_id TEXT NOT NULL,
 id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 contact_id TEXT NOT NULL,
 contact_version INT NOT NULL CHECK (contact_version > 0),
 code_digest TEXT NOT NULL CHECK (code_digest ~ '^[a-f0-9]{64}$'),
 sealed_code TEXT NOT NULL,
 attempts INT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
 expires_at TIMESTAMPTZ NOT NULL,
 consumed_at TIMESTAMPTZ,
 sent_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id,id),
 FOREIGN KEY (tenant_id,user_id,contact_id) REFERENCES user_contacts(tenant_id,user_id,id) ON DELETE CASCADE,
 CHECK (expires_at > created_at)
);
CALL synapse_enable_tenant_rls('user_contact_challenges');
CREATE INDEX user_contact_challenges_active ON user_contact_challenges(tenant_id,user_id,contact_id,created_at DESC) WHERE consumed_at IS NULL;

-- Persistent per-user quota survives contact replacement and API restarts.
CREATE TABLE user_contact_verification_requests (
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id,id),
 FOREIGN KEY (tenant_id,user_id) REFERENCES users(ownership_tenant_id,id)
);
CALL synapse_enable_tenant_rls('user_contact_verification_requests');
CREATE INDEX user_contact_verification_requests_recent ON user_contact_verification_requests(tenant_id,user_id,created_at DESC);

-- +goose Down
DROP TABLE user_contact_verification_requests;
DROP TABLE user_contact_challenges;
DROP TABLE user_contacts;
