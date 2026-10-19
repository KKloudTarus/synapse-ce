-- +goose Up
CREATE INDEX document_schedules_ready_idx
    ON document_schedules(tenant_id,next_due_at,id) WHERE enabled;
CREATE INDEX document_schedule_occurrences_ready_idx
    ON document_schedule_occurrences(tenant_id,updated_at,id)
    INCLUDE(schedule_id,schedule_version,state,lease_until)
    WHERE state IN ('pending','failed','in_flight');

-- +goose Down
DROP INDEX document_schedule_occurrences_ready_idx;
DROP INDEX document_schedules_ready_idx;
