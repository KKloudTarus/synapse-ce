-- +goose Up
-- Self-hosted forge API base for pull request decoration (GitHub Enterprise Server, self-managed
-- GitLab). Empty keeps the provider's public SaaS API, so existing rows keep today's behaviour.
--
-- The value is validated in the domain (https, no userinfo/query/fragment, clean path, host equal to
-- the row's host) and against the operator host allowlist before it is written. A non-empty base is
-- also part of the token's AES-GCM AAD, so a database write that changes it leaves the sealed token
-- undecryptable: the credential cannot be redirected to another API without re-entering it.
ALTER TABLE scm_connectors ADD COLUMN api_base TEXT NOT NULL DEFAULT '';
ALTER TABLE scm_connectors ADD CONSTRAINT scm_connectors_api_base_https
    CHECK (api_base = '' OR (api_base LIKE 'https://%' AND length(api_base) <= 512));

-- +goose Down
ALTER TABLE scm_connectors DROP CONSTRAINT IF EXISTS scm_connectors_api_base_https;
ALTER TABLE scm_connectors DROP COLUMN IF EXISTS api_base;
