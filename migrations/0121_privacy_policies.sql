-- +goose Up
-- Immutable tenant source-privacy policy history. Active selection remains a
-- separate mutable pointer so delayed telemetry can authorize its historical
-- redaction-policy digest without rewriting prior policy facts.
CREATE TABLE privacy_policies (
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    policy_version TEXT NOT NULL CHECK (btrim(policy_version) <> ''),
    policy         JSONB NOT NULL CHECK (jsonb_typeof(policy) = 'object'),
    digest         TEXT NOT NULL,
    created_by     TEXT NOT NULL CHECK (btrim(created_by) <> ''),
    created_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, policy_version),
    UNIQUE (tenant_id, digest),
    CONSTRAINT privacy_policies_digest_sha256 CHECK (digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE privacy_active_policies (
    tenant_id      TEXT PRIMARY KEY REFERENCES tenants(id),
    policy_version TEXT NOT NULL,
    activated_at   TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, policy_version)
        REFERENCES privacy_policies(tenant_id, policy_version)
);

CALL synapse_enable_tenant_rls('privacy_policies');
CALL synapse_enable_tenant_rls('privacy_active_policies');

CREATE TRIGGER privacy_policies_append_only
    BEFORE UPDATE OR DELETE ON privacy_policies
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER privacy_policies_no_truncate
    BEFORE TRUNCATE ON privacy_policies
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER privacy_active_policies_no_truncate
    BEFORE TRUNCATE ON privacy_active_policies
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
-- Historical policy identities may already authenticate retained telemetry.
-- Refuse rollback rather than deleting accepted authorization facts.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM privacy_policies) THEN
        RAISE EXCEPTION 'cannot roll back 0121: privacy policy history exists';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS privacy_active_policies_no_truncate ON privacy_active_policies;
DROP TRIGGER IF EXISTS privacy_policies_no_truncate ON privacy_policies;
DROP TRIGGER IF EXISTS privacy_policies_append_only ON privacy_policies;
DROP TABLE privacy_active_policies;
DROP TABLE privacy_policies;
