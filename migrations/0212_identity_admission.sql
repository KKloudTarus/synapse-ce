-- +goose Up
-- Admission augments the foundation transaction record with sealed callback context. The
-- existing state digest remains the sole externally supplied lookup key.
ALTER TABLE identity_transactions
    ADD COLUMN context_sealed TEXT NOT NULL DEFAULT '' CHECK (octet_length(context_sealed) <= 4096);
ALTER TABLE identity_transactions
    ADD COLUMN caller_nonce_digest TEXT NOT NULL DEFAULT '' CHECK (caller_nonce_digest = '' OR caller_nonce_digest ~ '^[0-9a-f]{64}$');

ALTER TABLE identity_transactions DROP CONSTRAINT identity_transactions_purpose_check;
ALTER TABLE identity_transactions ADD CONSTRAINT identity_transactions_purpose_check
    CHECK (purpose IN ('login', 'link', 'switch', 'step_up', 'invitation', 'test'));

ALTER TABLE identity_invitations
    ADD COLUMN version INT NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 7);
CREATE INDEX identity_invitations_pending_recipient
    ON identity_invitations(tenant_id, recipient, expires_at) WHERE state = 'pending';

-- Challenge values are encrypted and never placed in outbound jobs, templates, logs, or URLs.
CREATE TABLE identity_invitation_challenges (
    tenant_id TEXT NOT NULL CHECK (tenant_id <> ''),
    invitation_id TEXT NOT NULL,
    invitation_version INT NOT NULL CHECK (invitation_version BETWEEN 1 AND 7),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 1024),
    prospective_person_id TEXT NOT NULL CHECK (length(prospective_person_id) BETWEEN 1 AND 128),
    challenge_digest TEXT NOT NULL CHECK (challenge_digest ~ '^[0-9a-f]{64}$'),
    challenge_sealed TEXT NOT NULL CHECK (length(challenge_sealed) BETWEEN 1 AND 4096),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, invitation_id, invitation_version, subject),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES identity_invitations(tenant_id, id),
    CHECK (expires_at > created_at)
);
CREATE INDEX identity_invitation_challenges_cleanup
    ON identity_invitation_challenges(tenant_id, expires_at) WHERE consumed_at IS NULL;
CALL synapse_enable_tenant_rls('identity_invitation_challenges');

-- A revision can only be considered once under a one-use protocol transaction. This captures
-- successful upstream proof separately from connection creation/discovery.
CREATE TABLE identity_connection_protocol_proofs (
    tenant_id TEXT NOT NULL CHECK (tenant_id <> ''),
    connection_id TEXT NOT NULL,
    revision INT NOT NULL CHECK (revision > 0),
    transaction_id TEXT NOT NULL,
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 1024),
    authenticated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, transaction_id),
    FOREIGN KEY (tenant_id, connection_id, revision) REFERENCES identity_connection_revisions(tenant_id, connection_id, revision),
    FOREIGN KEY (tenant_id, transaction_id) REFERENCES identity_transactions(tenant_id, id)
);
CREATE INDEX identity_connection_protocol_proofs_revision
    ON identity_connection_protocol_proofs(tenant_id, connection_id, revision, created_at DESC);
CALL synapse_enable_tenant_rls('identity_connection_protocol_proofs');
CREATE TRIGGER identity_connection_protocol_proofs_append_only BEFORE UPDATE OR DELETE ON identity_connection_protocol_proofs
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_append_only();

-- +goose Down
ALTER TABLE identity_invitation_challenges NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_connection_protocol_proofs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_transactions NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM identity_invitation_challenges)
       OR EXISTS (SELECT 1 FROM identity_connection_protocol_proofs)
       OR EXISTS (SELECT 1 FROM identity_transactions WHERE context_sealed <> '') THEN
        RAISE EXCEPTION 'identity admission evidence requires a forward fix';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE identity_connection_protocol_proofs;
DROP TABLE identity_invitation_challenges;
DROP INDEX identity_invitations_pending_recipient;
ALTER TABLE identity_invitations DROP COLUMN version;
ALTER TABLE identity_transactions DROP CONSTRAINT identity_transactions_purpose_check;
ALTER TABLE identity_transactions ADD CONSTRAINT identity_transactions_purpose_check
    CHECK (purpose IN ('login', 'link', 'switch', 'step_up', 'invitation'));
ALTER TABLE identity_transactions DROP COLUMN context_sealed;
ALTER TABLE identity_transactions DROP COLUMN caller_nonce_digest;
ALTER TABLE identity_transactions FORCE ROW LEVEL SECURITY;
