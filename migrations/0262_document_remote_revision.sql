-- +goose Up
-- Some document providers expose a conditional-write token that is opaque to
-- Synapse. Keep it beside the historical numeric version so Confluence rows
-- and released command history remain compatible.
ALTER TABLE document_links
    ADD COLUMN remote_revision TEXT NOT NULL DEFAULT ''
        CHECK (remote_revision='' OR (octet_length(remote_revision) BETWEEN 1 AND 512 AND btrim(remote_revision) <> ''));
ALTER TABLE document_intents
    ADD COLUMN remote_revision TEXT NOT NULL DEFAULT ''
        CHECK (remote_revision='' OR (octet_length(remote_revision) BETWEEN 1 AND 512 AND btrim(remote_revision) <> ''));

-- +goose Down
-- A rollback must not silently discard a provider concurrency token. Disable
-- FORCE RLS only inside this migration transaction so the guard sees all tenants.
LOCK TABLE document_links IN ACCESS EXCLUSIVE MODE;
LOCK TABLE document_intents IN ACCESS EXCLUSIVE MODE;
ALTER TABLE document_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE document_intents NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM document_links WHERE remote_revision <> '')
        OR EXISTS (SELECT 1 FROM document_intents WHERE remote_revision <> '') THEN
        RAISE EXCEPTION 'cannot roll back document remote revisions while opaque revision data exists'
            USING ERRCODE = '55000';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE document_links DROP COLUMN remote_revision;
ALTER TABLE document_intents DROP COLUMN remote_revision;
ALTER TABLE document_links FORCE ROW LEVEL SECURITY;
ALTER TABLE document_intents FORCE ROW LEVEL SECURITY;
