-- +goose Up
-- Phase 4 hardening (PR3, golden rules 5 + 6): make the evidence + audit custody chains
-- TAMPER-RESISTANT at the database level, not merely tamper-evident.
--
-- 1) Audit fork-guard – parity with the evidence chain (0026). A partial unique index on
--    previous_hash (chained rows only; legacy pre-0021 rows have NULL previous_hash and are
--    excluded) means one child per parent: two rows can never claim the same parent hash, so
--    the chain cannot FORK. This is the structural guarantee beyond the advisory-lock write
--    discipline the Record path already uses. The genesis row (previous_hash = '') is covered
--    too, so the chain has a single root.
CREATE UNIQUE INDEX audit_chain_link_uniq ON audit_log (previous_hash) WHERE previous_hash IS NOT NULL;

-- 2) Append-only enforcement – block UPDATE / DELETE / TRUNCATE on both custody tables at the
--    DB level. A row, once sealed into a chain, can never be edited or removed in-band, so a
--    TAIL-TRUNCATION (delete the latest links to hide an action) or a row-edit is impossible
--    through the normal connection – not just detectable after the fact. Both tables are
--    INSERT-only in the application (evidence re-chains by INSERTing a fresh link on a fork
--    conflict; audit only ever inserts), so this changes no live code path. A superuser can
--    still DISABLE a trigger; the hash chain + ed25519 head attestation + RFC-3161 anchor
--    remain the out-of-band detection for that residual.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_forbid_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'append-only: % on % is forbidden (custody chain, golden rule 6)', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER evidence_append_only
    BEFORE UPDATE OR DELETE ON evidence
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER evidence_no_truncate
    BEFORE TRUNCATE ON evidence
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;
DROP TRIGGER IF EXISTS evidence_no_truncate ON evidence;
DROP TRIGGER IF EXISTS evidence_append_only ON evidence;
DROP FUNCTION IF EXISTS synapse_forbid_mutation();
DROP INDEX IF EXISTS audit_chain_link_uniq;
