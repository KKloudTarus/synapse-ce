-- +goose Up
ALTER TABLE identity_invitations ADD COLUMN accepted_session_id TEXT;
ALTER TABLE identity_invitations ADD COLUMN accepted_payload_hash TEXT CHECK(accepted_payload_hash IS NULL OR accepted_payload_hash ~ '^[a-f0-9]{64}$');
ALTER TABLE identity_invitations ADD CONSTRAINT identity_invitation_accepted_session_fk FOREIGN KEY(tenant_id,accepted_session_id) REFERENCES identity_sessions(tenant_id,id);

-- +goose Down
ALTER TABLE identity_invitations NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM identity_invitations WHERE accepted_session_id IS NOT NULL) THEN
   RAISE EXCEPTION 'populated invitation retry evidence requires forward repair';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE identity_invitations DROP CONSTRAINT identity_invitation_accepted_session_fk;
ALTER TABLE identity_invitations DROP COLUMN accepted_session_id, DROP COLUMN accepted_payload_hash;
ALTER TABLE identity_invitations FORCE ROW LEVEL SECURITY;
