-- +goose Up
-- Leader election (#406, epic #405): a fenced lease so more than one synapse-api / synapse-worker
-- instance can run concurrently while exactly one is the scheduler leader at a time.
--
-- DELIBERATELY NOT tenant-scoped and NOT under RLS: a leadership lease is global control-plane
-- infrastructure, not customer data (a documented exception to the tenant-table convention, like
-- advisories in 0038). There is nothing tenant-private to isolate.
--
-- `fence` is a monotonically increasing token bumped on every takeover; a partitioned old leader
-- that later tries to act can be rejected by comparing its stale fence against the current one.
CREATE TABLE leader_leases (
    resource     TEXT PRIMARY KEY,
    holder       TEXT NOT NULL,
    fence        BIGINT NOT NULL DEFAULT 0,
    term_expires TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE leader_leases;
