-- +goose Up
-- Phase E (tenant foundation): give users a tenant_id so the authenticated Principal can carry a
-- tenant that propagates into writes (and, in PR5c, scopes reads). Default '' = the single
-- default tenant (migration 0002), so single-tenant behavior is UNCHANGED – this only adds the
-- SOURCE the Principal resolves its tenant from. Architectural preparation, not full SaaS.
ALTER TABLE users ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE users DROP COLUMN tenant_id;
