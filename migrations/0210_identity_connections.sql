-- +goose Up
ALTER TABLE identity_connections ADD COLUMN version INT NOT NULL DEFAULT 1 CHECK (version > 0);
CREATE TABLE identity_connection_tests (
    tenant_id TEXT NOT NULL CHECK (tenant_id <> ''),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    connection_id TEXT NOT NULL,
    revision INT NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (state IN ('passed', 'failed')),
    tested_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CHECK (expires_at > tested_at),
    FOREIGN KEY (tenant_id, connection_id, revision)
        REFERENCES identity_connection_revisions(tenant_id, connection_id, revision)
);
CREATE INDEX identity_connection_tests_revision ON identity_connection_tests(tenant_id, connection_id, revision, tested_at DESC);
CALL synapse_enable_tenant_rls('identity_connection_tests');
CREATE TRIGGER identity_connection_tests_append_only BEFORE UPDATE OR DELETE ON identity_connection_tests
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_append_only();

-- +goose Down
ALTER TABLE identity_connection_tests NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM identity_connection_tests) THEN
        RAISE EXCEPTION 'identity connection test evidence requires a forward fix';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE identity_connection_tests;
ALTER TABLE identity_connections DROP COLUMN version;
