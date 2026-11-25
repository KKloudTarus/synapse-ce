-- +goose Up
-- The RFC-3161 anchor was the only custody store that could be rewritten.
--
-- migrations/0033_evidence_audit_append_only.sql makes evidence and audit_log append-only and then
-- names what is left: "A superuser can still DISABLE a trigger; the hash chain + ed25519 head
-- attestation + RFC-3161 anchor remain the out-of-band detection for that residual."
-- timestamp_tokens IS that anchor, and migration 0022 says so in its own header: the external token
-- is what makes a chain tamper-proof, because an operator who reforges and re-signs a chain still
-- cannot backdate a trusted timestamp.
--
-- It had no trigger, no row-level security and no revoke, while every other custody table had all
-- three. The runtime role could UPDATE and DELETE it, measured against a migrated database with a
-- NOSUPERUSER NOBYPASSRLS role: deleting the anchors for a chain leaves LatestHead with nothing to
-- return, and the tail-truncation check in internal/usecase/evidence degrades from "the anchor says
-- head X existed at time T" to "no anchor was recorded".
--
-- The store inserts and selects only (internal/infrastructure/persistence/postgres/timestamp_store.go
-- has no update or delete path) and nothing references the table, so unlike observation_finding_bindings
-- there is no cascade a BEFORE DELETE trigger would break. The trigger is therefore the right tool
-- here and REVOKE is not needed.
CREATE TRIGGER timestamp_tokens_append_only
    BEFORE UPDATE OR DELETE ON timestamp_tokens
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();

CREATE TRIGGER timestamp_tokens_no_truncate
    BEFORE TRUNCATE ON timestamp_tokens
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS timestamp_tokens_no_truncate ON timestamp_tokens;
DROP TRIGGER IF EXISTS timestamp_tokens_append_only ON timestamp_tokens;
