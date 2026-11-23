-- +goose Up
-- Destination-managed snapshots publish immutable pages. The profile and
-- expected local-link revision are frozen with each command so an integration
-- edit cannot alter a pending write's authorization semantics.
ALTER TABLE document_links
    ADD COLUMN access_profile TEXT NOT NULL DEFAULT '' CHECK (access_profile IN ('','destination_managed_snapshot_v1')),
    ADD COLUMN removal_kind TEXT NOT NULL DEFAULT '' CHECK (removal_kind IN ('','trash','purge'));
ALTER TABLE document_links DROP CONSTRAINT document_links_restriction_status_check;
ALTER TABLE document_links ADD CONSTRAINT document_links_restriction_status_check
    CHECK (restriction_status IN ('unchecked','verified','restriction_lost','unverifiable','destination_managed'));
ALTER TABLE document_intents
    ADD COLUMN expected_link_revision INT NOT NULL DEFAULT 0 CHECK (expected_link_revision >= 0),
    ADD COLUMN access_profile TEXT NOT NULL DEFAULT '' CHECK (access_profile IN ('','destination_managed_snapshot_v1'));
ALTER TABLE document_commands
    ADD COLUMN access_profile TEXT NOT NULL DEFAULT '' CHECK (access_profile IN ('','destination_managed_snapshot_v1'));

-- Strict purge rows from earlier releases already have a retirement time. Fill
-- their truthful historical removal kind before adding the paired invariant.
LOCK TABLE document_links IN ACCESS EXCLUSIVE MODE;
ALTER TABLE document_links NO FORCE ROW LEVEL SECURITY;
UPDATE document_links SET removal_kind='purge' WHERE retired_at IS NOT NULL;
ALTER TABLE document_links FORCE ROW LEVEL SECURITY;

ALTER TABLE document_intents DROP CONSTRAINT document_intents_action_check;
ALTER TABLE document_intents ADD CONSTRAINT document_intents_action_check CHECK (action IN ('create','update','purge','snapshot','trash'));
ALTER TABLE document_intents DROP CONSTRAINT document_intents_link_action_check;
ALTER TABLE document_intents ADD CONSTRAINT document_intents_link_action_check CHECK ((action='create') = (link_id IS NULL));
ALTER TABLE document_intents ADD CONSTRAINT document_intents_managed_snapshot_check CHECK (
    (action IN ('snapshot','trash') AND expected_link_revision > 0 AND access_profile='destination_managed_snapshot_v1') OR
    (action NOT IN ('snapshot','trash') AND expected_link_revision=0)
);
ALTER TABLE document_links ADD CONSTRAINT document_links_removal_state_check CHECK ((retired_at IS NULL) = (removal_kind=''));

-- +goose Down
LOCK TABLE document_commands,document_links,document_intents IN ACCESS EXCLUSIVE MODE;
ALTER TABLE document_commands NO FORCE ROW LEVEL SECURITY;
ALTER TABLE document_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE document_intents NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM document_intents WHERE action IN ('snapshot','trash') OR access_profile <> '' OR expected_link_revision <> 0)
    OR EXISTS (SELECT 1 FROM document_links WHERE access_profile <> '' OR removal_kind='trash')
    OR EXISTS (SELECT 1 FROM document_commands WHERE access_profile <> '') THEN
  RAISE EXCEPTION 'cannot roll back managed document snapshots while managed data exists' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE document_intents DROP CONSTRAINT document_intents_managed_snapshot_check;
ALTER TABLE document_links DROP CONSTRAINT document_links_removal_state_check;
ALTER TABLE document_links DROP CONSTRAINT document_links_restriction_status_check;
ALTER TABLE document_links ADD CONSTRAINT document_links_restriction_status_check
    CHECK (restriction_status IN ('unchecked','verified','restriction_lost','unverifiable'));
ALTER TABLE document_intents DROP CONSTRAINT document_intents_link_action_check;
ALTER TABLE document_intents DROP CONSTRAINT document_intents_action_check;
ALTER TABLE document_intents ADD CONSTRAINT document_intents_action_check CHECK (action IN ('create','update','purge'));
ALTER TABLE document_intents ADD CONSTRAINT document_intents_link_action_check CHECK ((action='create') = (link_id IS NULL));
ALTER TABLE document_commands DROP COLUMN access_profile;
ALTER TABLE document_intents DROP COLUMN access_profile, DROP COLUMN expected_link_revision;
ALTER TABLE document_links DROP COLUMN removal_kind, DROP COLUMN access_profile;
ALTER TABLE document_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE document_links FORCE ROW LEVEL SECURITY;
ALTER TABLE document_intents FORCE ROW LEVEL SECURITY;
