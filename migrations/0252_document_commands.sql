-- +goose Up
ALTER TABLE document_links ADD COLUMN retired_at TIMESTAMPTZ;

ALTER TABLE document_intents DROP CONSTRAINT document_intents_action_check;
-- The link-action check was anonymous in 0241 while the marker invariant is
-- also anonymous. Locate the former by its expression; never drop the marker.
-- +goose StatementBegin
DO $$ DECLARE constraint_name TEXT; BEGIN
 SELECT conname INTO constraint_name FROM pg_constraint
 WHERE conrelid='document_intents'::regclass AND contype='c'
   AND pg_get_constraintdef(oid) LIKE '%action%create%' AND pg_get_constraintdef(oid) LIKE '%link_id%'
 LIMIT 1;
 IF constraint_name IS NOT NULL THEN EXECUTE format('ALTER TABLE document_intents DROP CONSTRAINT %I', constraint_name); END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE document_intents ADD CONSTRAINT document_intents_action_check
 CHECK (action IN ('create','update','purge'));
ALTER TABLE document_intents ADD CONSTRAINT document_intents_link_action_check
 CHECK ((action='create') = (link_id IS NULL));

CREATE TABLE document_commands (
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 intent_id TEXT NOT NULL,
 actor_user_id TEXT NOT NULL,
 actor_membership_id TEXT NOT NULL,
 actor_person_id TEXT NOT NULL,
 connection_revision INT NOT NULL CHECK(connection_revision>0),
 credential_revision INT NOT NULL CHECK(credential_revision>=0),
 read_group TEXT NOT NULL CHECK(octet_length(read_group) BETWEEN 1 AND 255 AND btrim(read_group)<>''),
 artifact JSONB NOT NULL CHECK(jsonb_typeof(artifact)='object' AND octet_length(artifact::text)<=33554432 AND octet_length(COALESCE(artifact->>'PDF',''))<=13981016),
 progress JSONB NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(progress)='object' AND octet_length(progress::text)<=1048576),
 progress_version INT NOT NULL DEFAULT 1 CHECK(progress_version>0),
 created_at TIMESTAMPTZ NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(tenant_id,intent_id),
 FOREIGN KEY(tenant_id,intent_id) REFERENCES document_intents(tenant_id,id) ON DELETE RESTRICT,
 CHECK(updated_at>=created_at)
);
CREATE INDEX document_commands_pending_idx ON document_commands(tenant_id,updated_at,intent_id);
CALL synapse_enable_tenant_rls('document_commands');

-- +goose Down
-- +goose StatementBegin
LOCK TABLE document_commands,document_links,document_intents IN ACCESS EXCLUSIVE MODE;
ALTER TABLE document_commands NO FORCE ROW LEVEL SECURITY;
ALTER TABLE document_links NO FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM document_commands) OR EXISTS(SELECT 1 FROM document_links WHERE retired_at IS NOT NULL) THEN
  RAISE EXCEPTION 'cannot roll back document commands while durable command data exists' USING ERRCODE='55000';
 END IF;
END $$;
ALTER TABLE document_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE document_links FORCE ROW LEVEL SECURITY;
-- +goose StatementEnd
DROP INDEX document_commands_pending_idx;
DROP TABLE document_commands;
ALTER TABLE document_intents DROP CONSTRAINT document_intents_link_action_check;
ALTER TABLE document_intents DROP CONSTRAINT document_intents_action_check;
ALTER TABLE document_intents ADD CONSTRAINT document_intents_action_check CHECK (action IN ('create','update'));
ALTER TABLE document_links DROP COLUMN retired_at;
