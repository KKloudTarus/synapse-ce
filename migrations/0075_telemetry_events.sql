-- +goose Up
-- Columnar telemetry tier (issue #424, ADR 0001). This is the CE milestone store behind
-- ports.TelemetryStore: a time-indexed raw-event table with tiered retention. It is NEVER in the path of
-- a finding, a judgment, or the evidence chain, and it appears in no domain type. At fleet scale this
-- table is served by ClickHouse behind the same port (ADR 0001); the schema here proves the contract on
-- a volume a single Postgres node serves.
--
-- Telemetry is NOT hash-chained per event (#405): rows are mutable/deletable so retention can down-sample
-- the warm window and expire the past-warm window. Batches stay sequence-numbered (seq) so a hunt sees a
-- complete vs. lossy sequence.
CREATE TABLE telemetry_events (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    host_id     TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    class       TEXT NOT NULL,
    seq         BIGINT NOT NULL,
    idx         INT NOT NULL,
    sample_rate INT NOT NULL DEFAULT 1,   -- 1 = full fidelity; N = 1-in-N (recorded WITH the data)
    event       JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    tier        TEXT NOT NULL DEFAULT 'hot' CHECK (tier IN ('hot', 'warm')),
    PRIMARY KEY (tenant_id, host_id, class, seq, idx)
);

-- BRIN on the time column is the cheap, time-ordered index appropriate for append-mostly telemetry — the
-- columnar-style access pattern retro hunting uses (scan a time window), at a fraction of a btree's size.
CREATE INDEX idx_telemetry_observed ON telemetry_events USING BRIN (observed_at);
CREATE INDEX idx_telemetry_asset    ON telemetry_events (tenant_id, asset_id, observed_at);
-- A (tenant_id, host_id, class, seq) lookup (LastSequence, sequence-gap scan) is served by the PRIMARY
-- KEY (tenant_id, host_id, class, seq, idx) btree's leading prefix, so no separate index is needed.

CALL synapse_enable_tenant_rls('telemetry_events');

-- +goose Down
DROP TABLE telemetry_events;
