-- +goose Up
-- Record which preimage encoding produced each chain hash. Scheme 1 is the original
-- separator-terminated encoding, whose field boundaries are ambiguous. Scheme 2 length-prefixes
-- every field. Existing rows were all hashed under scheme 1, which the default records, and a
-- binary that predates this column keeps writing scheme 1 rows through the same default, so the
-- migration is safe to apply before any binary is deployed. Binaries in the release carrying this
-- migration read the column but still write scheme 1, because an older binary that reads a scheme 2
-- row recomputes it as scheme 1 and reports tamper. Writers move to scheme 2 one release later.
--
-- The column is deliberately separate from audit_log.hash_version. hash_version names the chain
-- topology (1: the global legacy chain, 2: one chain per tenant), and the tenant RLS policy, the
-- v2 fork guard and the SIEM export all select on it. The encoding is an independent axis.
--
-- Every statement is idempotent because Down keeps the columns; see below. lock_timeout bounds how
-- long the migration queues behind a long reader, because every writer queues behind it in turn.
SET LOCAL lock_timeout = '5s';
ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS hash_scheme SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_hash_scheme_check;
-- NOT VALID here, validated by 0274. Goose runs each file in one transaction, so a validating scan
-- in this file would hold ACCESS EXCLUSIVE on audit_log for the length of both table scans and block
-- every audit write (measured: 1.8 s at 5M audit rows, linear in heap size). 0274 validates under
-- SHARE UPDATE EXCLUSIVE, which writers do not wait on.
ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_hash_scheme_check CHECK (hash_scheme IN (1, 2)) NOT VALID;

ALTER TABLE evidence
    ADD COLUMN IF NOT EXISTS hash_scheme SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE evidence DROP CONSTRAINT IF EXISTS evidence_hash_scheme_check;
ALTER TABLE evidence
    ADD CONSTRAINT evidence_hash_scheme_check CHECK (hash_scheme IN (1, 2)) NOT VALID;

-- +goose Down
-- The columns stay. Dropping them would leave every scheme 2 row with no record of the encoding
-- that produced its hash, so no binary could ever verify it again, and both tables are
-- append-only, so the rows cannot be rehashed instead. A binary from before this migration ignores
-- the columns and writes scheme 1 through the default, which is the encoding it computes. It also
-- reads every row as scheme 1, so rolling back past the release that writes scheme 2 reports those
-- rows as tampered; roll back only to a release that reads the column.
SELECT 1;
