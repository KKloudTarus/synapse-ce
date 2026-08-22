-- +goose Up
-- A3 (#624) agent→control-plane telemetry transport state, kept separate from the columnar
-- telemetry_events tier: it holds the incarnation-aware (stream, epoch) delivery bookkeeping the
-- columnar (host, class, seq) store does not model — the highest-contiguous ACK snapshot and the durable
-- raw batch events. Transport gaps are NOT a separate table: they are derived on read from the ACK snapshot
-- (contiguous + pending → AckLedger.Gaps()), which is the single source of truth, so a filled gap can never
-- linger as a phantom. Like telemetry_events these rows are mutable/expirable and NOT hash-chained: they are
-- transport honesty, never evidence. Both tables are tenant-scoped RLS.

-- Per-(stream, epoch) AckLedger snapshot: the highest sequence with no hole beneath it (the ACK) and the
-- received-but-not-yet-contiguous sequences (pending). Rehydrating an AckLedger from this recomputes the
-- ACK on the next batch without replaying every sequence. A reboot mints a new epoch row, so a
-- reset-to-1 in a new incarnation is a fresh sequence, never a replay of the previous incarnation.
-- The transport identity key includes agent_id: a StreamID is chosen by the agent, so keying delivery
-- state on (tenant, stream) alone would let one compromised agent hijack a sibling agent's stream within
-- the same tenant (force a stale-incarnation reject, or falsely advance its ACK so it deletes un-acked
-- batches). Namespacing by the AUTHENTICATED agent_id gives each agent its own stream space, closing that
-- intra-tenant cross-agent vector (A0.1 server-authoritative identity for the stream partition).
CREATE TABLE telemetry_stream_positions (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    agent_id   TEXT NOT NULL,
    stream_id  TEXT NOT NULL,
    epoch      BIGINT NOT NULL,
    contiguous BIGINT NOT NULL DEFAULT 0,
    pending    BIGINT[] NOT NULL DEFAULT '{}',
    -- version is an optimistic-concurrency guard: an ingest reads (contiguous, pending, version),
    -- classifies, then writes back only if version is unchanged (else it retries). This serializes
    -- concurrent batches for one (agent, stream, epoch) so a lost update cannot regress the ACK or
    -- fabricate a gap.
    version    BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, stream_id, epoch),
    CONSTRAINT telemetry_stream_positions_epoch_check CHECK (epoch >= 1),
    CONSTRAINT telemetry_stream_positions_contiguous_check CHECK (contiguous >= 0)
);
CREATE INDEX idx_telemetry_stream_positions_stream ON telemetry_stream_positions (tenant_id, agent_id, stream_id, epoch);
CALL synapse_enable_tenant_rls('telemetry_stream_positions');

-- Durable raw batch events: the opaque shipped bytes of each accepted event, content-addressed by digest,
-- carrying the wire schema_version (A0.3), keyed by the incarnation-aware (agent, stream, epoch, seq, event_id)
-- so a re-delivered batch stores each event at most once (idempotent ingest). agent_id is in the key for the
-- same reason as the positions table: an agent-chosen StreamID must never let one agent write into another
-- agent's stream space within the tenant.
CREATE TABLE telemetry_batch_events (
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    agent_id       TEXT NOT NULL,
    stream_id      TEXT NOT NULL,
    asset_id       TEXT NOT NULL,
    epoch          BIGINT NOT NULL,
    sequence       BIGINT NOT NULL,
    event_id       TEXT NOT NULL,
    class          TEXT NOT NULL,
    digest         TEXT NOT NULL,
    schema_version INT NOT NULL,
    payload        BYTEA NOT NULL,
    observed_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, stream_id, epoch, sequence, event_id),
    CONSTRAINT telemetry_batch_events_schema_check CHECK (schema_version >= 1),
    CONSTRAINT telemetry_batch_events_seq_check CHECK (epoch >= 1 AND sequence >= 1)
);
CREATE INDEX idx_telemetry_batch_events_stream ON telemetry_batch_events (tenant_id, agent_id, stream_id, epoch, sequence);
CALL synapse_enable_tenant_rls('telemetry_batch_events');

-- +goose Down
DROP TABLE telemetry_batch_events;
DROP TABLE telemetry_stream_positions;
