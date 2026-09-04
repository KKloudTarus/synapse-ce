-- +goose Up
-- Assessment Cycle HTTP/idempotency schema.
-- A5 (#699): tenant-scoped retained responses for Cycle/Re-test API idempotency.

ALTER TABLE engagements
    ADD COLUMN requires_explicit_execution_authorization BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE assessment_cycle_api_requests (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    actor           TEXT NOT NULL,
    route           TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash    TEXT NOT NULL,
    status_code     INTEGER NULL,
    response_body   BYTEA NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ NULL,
    PRIMARY KEY (tenant_id, actor, route, idempotency_key),
    CONSTRAINT assessment_cycle_api_requests_actor_check CHECK (actor = btrim(actor) AND length(actor) BETWEEN 1 AND 256),
    CONSTRAINT assessment_cycle_api_requests_route_check CHECK (route = btrim(route) AND length(route) BETWEEN 1 AND 256),
    CONSTRAINT assessment_cycle_api_requests_key_check CHECK (idempotency_key = btrim(idempotency_key) AND length(idempotency_key) BETWEEN 1 AND 128),
    CONSTRAINT assessment_cycle_api_requests_hash_check CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT assessment_cycle_api_requests_response_check CHECK (
        (status_code IS NULL AND response_body IS NULL AND completed_at IS NULL) OR
        (status_code BETWEEN 200 AND 599 AND response_body IS NOT NULL AND completed_at IS NOT NULL AND octet_length(response_body) <= 2097152)
    )
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_guard_assessment_cycle_api_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.tenant_id <> NEW.tenant_id OR OLD.actor <> NEW.actor OR OLD.route <> NEW.route OR
       OLD.idempotency_key <> NEW.idempotency_key OR OLD.request_hash <> NEW.request_hash OR
       OLD.created_at <> NEW.created_at THEN
        RAISE EXCEPTION 'assessment cycle idempotency identity is immutable';
    END IF;
    IF OLD.completed_at IS NOT NULL THEN
        RAISE EXCEPTION 'completed assessment cycle idempotency response is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER assessment_cycle_api_requests_guard
BEFORE UPDATE ON assessment_cycle_api_requests
FOR EACH ROW EXECUTE FUNCTION synapse_guard_assessment_cycle_api_request();

CALL synapse_enable_tenant_rls('assessment_cycle_api_requests');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM assessment_cycle_api_requests LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back assessment cycle API idempotency while retained responses exist';
    END IF;
END;
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS assessment_cycle_api_requests;
DROP FUNCTION IF EXISTS synapse_guard_assessment_cycle_api_request();

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM engagements WHERE requires_explicit_execution_authorization LIMIT 1) THEN
        RAISE EXCEPTION 'cannot roll back explicit Re-test execution authorization while guarded engagements exist';
    END IF;
END;
$$;
-- +goose StatementEnd

ALTER TABLE engagements DROP COLUMN requires_explicit_execution_authorization;
