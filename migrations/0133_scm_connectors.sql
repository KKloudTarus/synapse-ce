-- +goose Up
-- Source-control connectors: a tenant-scoped git host + username + sealed personal access
-- token, so the server can clone a PRIVATE repository (a Project git SourceBinding) on that
-- host. The token_ciphertext column holds ONLY AES-256-GCM ciphertext (base64 of nonce|ct,
-- AAD-bound to tenant_id+id+host+username, so a database-write attacker cannot repoint the
-- connector's host/username and have the token decrypt for it) under the same master key as the vault
-- (SYNAPSE_VAULT_MASTER_KEY, process memory only). A database compromise alone does not yield
-- the token. The plaintext is resolved only at clone time and injected into git via
-- GIT_ASKPASS, never argv, never .git/config, never a log.
--
-- One connector per host per tenant (UNIQUE tenant_id, host): the acquirer resolves a clone
-- URL's host to a single credential, so an ambiguous second connector for the same host is
-- refused at write time.
CREATE TABLE scm_connectors (
    tenant_id        TEXT        NOT NULL REFERENCES tenants(id),
    id               TEXT        NOT NULL,
    name             TEXT        NOT NULL,
    provider         TEXT        NOT NULL,               -- github | gitlab | bitbucket | generic
    host             TEXT        NOT NULL,               -- normalized lowercase FQDN, e.g. github.com
    username         TEXT        NOT NULL,               -- git username the token authenticates as
    auth_kind        TEXT        NOT NULL,               -- pat
    token_ciphertext TEXT        NOT NULL,               -- base64(nonce|AES-256-GCM ciphertext)
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, host)
);

-- Standard, non-weakenable tenant isolation: ENABLE + FORCE RLS and one USING + WITH CHECK
-- policy keyed on synapse_current_tenant() (migration 0057).
CALL synapse_enable_tenant_rls('scm_connectors');

-- +goose Down
DROP POLICY IF EXISTS scm_connectors_tenant_isolation ON scm_connectors;
ALTER TABLE scm_connectors NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scm_connectors DISABLE ROW LEVEL SECURITY;
DROP TABLE scm_connectors;
