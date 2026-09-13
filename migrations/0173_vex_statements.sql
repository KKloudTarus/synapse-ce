-- +goose Up
-- Persisted VEX statements ingested for an engagement (#1064 part 2b).
--
-- VEX import was apply-and-forget: a vendor/human OpenVEX or CSAF document adjusted finding statuses and was
-- then discarded. A rescan's Upsert overwrites those findings back to open, silently dropping the assertion.
-- Retaining each statement lets the SCA pipeline RE-APPLY it against the fresh finding set after a rescan, so
-- an accepted-risk or not_affected decision survives re-scanning (subject to the reachability reconciliation:
-- a persisted not_affected still never suppresses a Synapse-reachable finding).
--
-- The faithful assertion is stored as JSON in `statement`, so it re-applies with the exact same match
-- semantics as the original import; `advisory` is denormalized for querying and audit.
--
-- Idempotency: the primary key is (tenant, engagement, digest), the digest being a stable content hash of the
-- assertion (advisory + status + justification + sorted products). Re-importing an identical assertion is a
-- no-op (its original insertion order is kept); a changed assertion is a distinct row.
--
-- `seq` is a monotonic insertion order used to REPLAY statements in import order on re-apply, so the
-- most-recent assertion wins per finding deterministically. Ordering by a timestamp alone is not enough:
-- statements of one document share (or nearly share) an ingest time, and a coarse clock would tie, letting a
-- later `affected` replay before an earlier `not_affected`. The identity sequence is import order by
-- construction, independent of clock resolution.
--
-- RLS-native via the 0057 procedure (tenant_id keys the policy; the empty tenant means DENY). engagement_id
-- is a logical cross-aggregate reference validated at the application layer, matching imported_findings.
CREATE TABLE vex_statements (
    seq           BIGINT GENERATED ALWAYS AS IDENTITY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    engagement_id TEXT NOT NULL,
    digest        TEXT NOT NULL CHECK (digest <> ''),
    advisory      TEXT NOT NULL CHECK (advisory <> ''),
    statement     JSONB NOT NULL,
    actor         TEXT NOT NULL DEFAULT '',
    ingested_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, engagement_id, digest)
);

-- Backs the per-engagement re-apply read (import order via seq).
CREATE INDEX vex_statements_engagement ON vex_statements (tenant_id, engagement_id, seq);

CALL synapse_enable_tenant_rls('vex_statements');

-- +goose Down
DROP TABLE vex_statements;
