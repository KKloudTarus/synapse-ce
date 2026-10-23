-- +goose Up
-- Provider throttles must survive worker restarts. Keep the command deadline
-- separate from leases and progress timestamps: neither records retry intent.
ALTER TABLE document_commands
    ADD COLUMN next_attempt_at TIMESTAMPTZ;
CREATE INDEX document_commands_due_idx
    ON document_commands(tenant_id,next_attempt_at,checked_at,check_version,intent_id)
    WHERE next_attempt_at IS NOT NULL;
CREATE INDEX document_intents_eligible_queue_idx
    ON document_intents(tenant_id,state,lease_until,id)
    WHERE state IN ('pending','uncertain','in_flight')
       OR (state='failed' AND attempts<5);

-- Poll targets reserve a future due time before provider I/O. `checked_at`
-- remains the actual observation time and is never a synthetic throttle mark.
ALTER TABLE ticket_inbound_poll_progress
    ADD COLUMN next_poll_at TIMESTAMPTZ NOT NULL DEFAULT '-infinity'::timestamptz;
CREATE INDEX ticket_inbound_poll_progress_due_idx
    ON ticket_inbound_poll_progress(tenant_id,next_poll_at,checked_at,version,intent_id);

-- +goose Down
-- Do not turn a provider-directed future delay into an immediate retry on a
-- downgraded worker. Disable FORCE RLS only while the cross-tenant rollback
-- guard checks every queued provider target; an exception rolls the whole
-- migration transaction back and preserves the protection mode.
LOCK TABLE document_commands IN ACCESS EXCLUSIVE MODE;
LOCK TABLE ticket_inbound_poll_progress IN ACCESS EXCLUSIVE MODE;
ALTER TABLE document_commands NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_inbound_poll_progress NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM document_commands WHERE next_attempt_at > clock_timestamp())
       OR EXISTS (SELECT 1 FROM ticket_inbound_poll_progress WHERE next_poll_at > clock_timestamp()) THEN
        RAISE EXCEPTION 'cannot roll back provider retry scheduling while future provider deferrals or poll claims exist'
            USING ERRCODE = '55000';
    END IF;
END $$;
-- +goose StatementEnd
DROP INDEX ticket_inbound_poll_progress_due_idx;
ALTER TABLE ticket_inbound_poll_progress DROP COLUMN next_poll_at;
DROP INDEX document_commands_due_idx;
DROP INDEX document_intents_eligible_queue_idx;
ALTER TABLE document_commands DROP COLUMN next_attempt_at;
ALTER TABLE document_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE ticket_inbound_poll_progress FORCE ROW LEVEL SECURITY;
