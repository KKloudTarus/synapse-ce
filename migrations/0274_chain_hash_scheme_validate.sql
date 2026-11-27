-- +goose Up
-- Validate the hash_scheme checks 0273 added NOT VALID. VALIDATE CONSTRAINT scans the table under
-- SHARE UPDATE EXCLUSIVE, so audit and evidence writes continue while it runs, and it fires no row
-- trigger, so the append-only guards on both tables stay enabled. It is a file of its own because
-- goose runs each file in one transaction: in 0273 the scan would have held that file's ACCESS
-- EXCLUSIVE lock for its whole length.
ALTER TABLE audit_log VALIDATE CONSTRAINT audit_log_hash_scheme_check;
ALTER TABLE evidence VALIDATE CONSTRAINT evidence_hash_scheme_check;

-- +goose Down
-- A validated constraint is no weaker than an unvalidated one; there is nothing to undo.
SELECT 1;
