-- +goose Up
-- Column defaults are metadata-only. The partial queue index covers active links.
ALTER TABLE document_links
 ADD COLUMN restriction_status TEXT NOT NULL DEFAULT 'unchecked'
   CHECK (restriction_status IN ('unchecked','verified','restriction_lost','unverifiable')),
 ADD COLUMN restriction_checked_at TIMESTAMPTZ,
 ADD COLUMN restriction_next_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch'::timestamptz,
 ADD COLUMN restriction_check_version INTEGER NOT NULL DEFAULT 0 CHECK (restriction_check_version >= 0);
CREATE INDEX document_links_restriction_due_idx
 ON document_links(tenant_id,restriction_next_at,id) WHERE retired_at IS NULL;

-- +goose Down
DROP INDEX document_links_restriction_due_idx;
ALTER TABLE document_links
 DROP COLUMN restriction_status,
 DROP COLUMN restriction_checked_at,
 DROP COLUMN restriction_next_at,
 DROP COLUMN restriction_check_version;
