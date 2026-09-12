-- +goose Up
-- Reserve the exact ordered bulk request before applying any independently atomic
-- item. A retry may finish remaining items but cannot substitute another request.
CREATE TABLE ownership_bulk_requests (
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 actor_id TEXT NOT NULL,
 request_key TEXT NOT NULL CHECK (length(request_key) BETWEEN 1 AND 200),
 request_hash TEXT NOT NULL CHECK (length(request_hash)=64),
 created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (tenant_id,actor_id,request_key),
 FOREIGN KEY (tenant_id,actor_id) REFERENCES users(ownership_tenant_id,id)
);
CALL synapse_enable_tenant_rls('ownership_bulk_requests');
CREATE TRIGGER ownership_bulk_requests_immutable BEFORE UPDATE OR DELETE ON ownership_bulk_requests
 FOR EACH ROW EXECUTE FUNCTION ownership_reject_mutation();
-- +goose Down
DROP TABLE ownership_bulk_requests;
