-- +goose Up
-- Each active-policy pointer transition is retained as an immutable governance
-- fact. operation_id makes exact transport retries idempotent; revision preserves
-- every intentional transition, including A -> B -> A.
CREATE TABLE privacy_policy_activations (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    operation_id    TEXT NOT NULL CHECK (btrim(operation_id) <> ''),
    revision        BIGINT NOT NULL CHECK (revision > 0),
    policy_digest   TEXT NOT NULL,
    policy_version  TEXT NOT NULL,
    activated_by    TEXT NOT NULL CHECK (btrim(activated_by) <> ''),
    activated_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, revision),
    FOREIGN KEY (tenant_id, policy_version)
        REFERENCES privacy_policies(tenant_id, policy_version),
    FOREIGN KEY (tenant_id, policy_digest)
        REFERENCES privacy_policies(tenant_id, digest),
    CONSTRAINT privacy_policy_activations_digest_sha256
        CHECK (policy_digest ~ '^[0-9a-f]{64}$')
);

CALL synapse_enable_tenant_rls('privacy_policy_activations');

CREATE TRIGGER privacy_policy_activations_append_only
    BEFORE UPDATE OR DELETE ON privacy_policy_activations
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER privacy_policy_activations_no_truncate
    BEFORE TRUNCATE ON privacy_policy_activations
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
-- Activation history is governance evidence and must not be silently discarded.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM privacy_policy_activations) THEN
        RAISE EXCEPTION 'cannot roll back 0123: privacy activation history exists';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS privacy_policy_activations_no_truncate ON privacy_policy_activations;
DROP TRIGGER IF EXISTS privacy_policy_activations_append_only ON privacy_policy_activations;
DROP TABLE privacy_policy_activations;
