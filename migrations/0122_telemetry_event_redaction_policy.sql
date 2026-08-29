-- +goose Up
-- Historical pre-A6 rows have no trustworthy source-policy identity. Keep those
-- rows explicitly unattributed; newly accepted telemetry requires a digest at
-- the use-case and persistence-port boundaries.
ALTER TABLE telemetry_batch_events
    ADD COLUMN redaction_policy_digest TEXT;

ALTER TABLE telemetry_batch_events
    ADD CONSTRAINT telemetry_batch_events_redaction_policy_digest_sha256
    CHECK (redaction_policy_digest IS NULL OR redaction_policy_digest ~ '^[0-9a-f]{64}$');

-- Accepted attribution must never be REWRITTEN: a detection's provenance binds to the
-- event's redaction_policy_digest, so silently changing it would forge the privacy
-- policy the telemetry was admitted under. Row DELETE stays permitted because raw
-- telemetry is retention-bound, not chained evidence — a pruned event resolves as
-- Missing, which is honest. TRUNCATE is never a legitimate retention path.
CREATE TRIGGER telemetry_batch_events_immutable_attribution
    BEFORE UPDATE ON telemetry_batch_events
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();
CREATE TRIGGER telemetry_batch_events_no_truncate
    BEFORE TRUNCATE ON telemetry_batch_events
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
-- Source-redaction attribution is immutable accepted telemetry evidence: refuse
-- rollback while any retained event carries it, rather than silently stripping
-- the attribution from telemetry that was admitted under it.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM telemetry_batch_events WHERE redaction_policy_digest IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0122: telemetry events carry redaction-policy attribution';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS telemetry_batch_events_no_truncate ON telemetry_batch_events;
DROP TRIGGER IF EXISTS telemetry_batch_events_immutable_attribution ON telemetry_batch_events;
ALTER TABLE telemetry_batch_events
    DROP CONSTRAINT telemetry_batch_events_redaction_policy_digest_sha256,
    DROP COLUMN redaction_policy_digest;
