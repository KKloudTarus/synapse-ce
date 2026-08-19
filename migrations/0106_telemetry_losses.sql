-- +goose Up
-- First-class telemetry loss records (#611, A0.6 — fixes D2). When the store-rate stage cuts a batch, the
-- loss is persisted HERE as its own row — Truncated (a prefix kept, tail dropped) or Dropped (observed
-- then lost) — instead of being smuggled into an elevated sample_rate on telemetry_events. A retro-hunt
-- reads the loss records intersecting its window and reports the window as incomplete, so a truncation can
-- never masquerade as a complete window (the D2 bug). Agent-side SAMPLING is not recorded here — it stays
-- on telemetry_events.sample_rate.
--
-- Like telemetry_events these rows are mutable/expirable (retention), NOT hash-chained: they are honesty
-- metadata for the lossy tier, never evidence. Idempotent on (tenant, host, class, seq, disposition) so a
-- re-ingest of the same over-budget batch records one loss.
CREATE TABLE telemetry_losses (
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    host_id        TEXT NOT NULL,
    asset_id       TEXT NOT NULL,   -- so an asset-pivot hunt windows the loss like it windows events
    class          TEXT NOT NULL,
    seq            BIGINT NOT NULL,
    disposition    TEXT NOT NULL CHECK (disposition IN ('truncated', 'dropped')),
    observed_count INT NOT NULL,
    kept_count     INT NOT NULL,
    dropped_count  INT NOT NULL,
    reason         TEXT NOT NULL,
    -- The observed-time SPAN of the dropped events. A hunt overlapping any part of the span surfaces the
    -- loss (window by overlap: to_at >= since AND from_at <= until) — a single point would miss a hunt
    -- whose window starts inside the span.
    from_at        TIMESTAMPTZ NOT NULL,
    to_at          TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, host_id, class, seq, disposition),
    CONSTRAINT telemetry_losses_counts_check CHECK (kept_count + dropped_count = observed_count AND dropped_count > 0),
    CONSTRAINT telemetry_losses_span_check CHECK (from_at <= to_at)
);

-- Hunts window losses by the span (BRIN on from_at, append-mostly) and pivot host/class or asset.
CREATE INDEX idx_telemetry_losses_from  ON telemetry_losses USING BRIN (from_at);
CREATE INDEX idx_telemetry_losses_host  ON telemetry_losses (tenant_id, host_id, class, from_at);
CREATE INDEX idx_telemetry_losses_asset ON telemetry_losses (tenant_id, asset_id, from_at);

CALL synapse_enable_tenant_rls('telemetry_losses');

-- +goose Down
DROP TABLE telemetry_losses;
