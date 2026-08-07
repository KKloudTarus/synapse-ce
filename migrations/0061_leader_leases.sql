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
-- Resign expires the lease (it does not delete the row), so the fence survives a graceful handover
-- and never resets to 1.
--
-- CLOCK: the lease term is currently compared against each instance's own wall clock (the elector
-- passes its clock's now into Acquire). This is safe against two simultaneous leaders regardless of
-- skew (the DB serializes the takeover upsert, so only one challenger wins), but a fast-clocked
-- challenger can take over up to its skew early. Operating assumption: NTP-bounded skew much
-- smaller than (term - 2*renew). Moving the arithmetic onto the database clock (now()) removes the
-- assumption entirely and is the hardening to do when a downstream first gates on the fence.
CREATE TABLE leader_leases (
    resource     TEXT PRIMARY KEY,
    holder       TEXT NOT NULL,
    fence        BIGINT NOT NULL DEFAULT 0,
    term_expires TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE leader_leases;
