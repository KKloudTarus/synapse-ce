-- +goose Up
ALTER TABLE ticket_groups ADD COLUMN revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0);

-- +goose Down
LOCK TABLE ticket_groups IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_groups NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM ticket_groups WHERE revision>0) THEN
  RAISE EXCEPTION 'cannot roll back ticket group command revisions while commands exist' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE ticket_groups FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_groups DROP COLUMN revision;
