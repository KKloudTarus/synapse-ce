-- +goose Up
-- Finding-linked evidence can be imported (#1722). A link's hash binds the finding id it was sealed
-- with, and an import gives every finding a new id, so the remapped link stopped matching its hash and
-- every bundle with a finding-linked link was refused. The import now records the sealed finding id on
-- the link's import marker (0280). The hash is computed over that id when it is present, and the
-- evidence row's finding_id carries the id of the finding on this instance. A link sealed here has no
-- marker row and so cannot carry a sealed id: its finding_id stays hash-bound. Nothing sealed is
-- updated. The marker table gains the same append-only guard as evidence, because a marker that
-- disappears would make the link read as tampered, and a marker that changed its sealed id would too.
SET LOCAL lock_timeout = '5s';
ALTER TABLE evidence_imports ADD COLUMN sealed_finding_id TEXT;
CREATE TRIGGER evidence_imports_append_only
    BEFORE UPDATE OR DELETE ON evidence_imports
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER evidence_imports_no_truncate
    BEFORE TRUNCATE ON evidence_imports
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
-- Links imported with a sealed finding id stop verifying once the column is gone; they cannot be
-- rehashed, because their rows are append-only.
SET LOCAL lock_timeout = '5s';
DROP TRIGGER IF EXISTS evidence_imports_no_truncate ON evidence_imports;
DROP TRIGGER IF EXISTS evidence_imports_append_only ON evidence_imports;
ALTER TABLE evidence_imports DROP COLUMN IF EXISTS sealed_finding_id;
