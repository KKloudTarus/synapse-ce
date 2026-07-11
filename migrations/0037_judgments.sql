-- +goose Up
-- Tier-0 (E27.5 / ADR-0021): AI "judgment" records – the propose->verify->confirm analysis
-- primitive (reachability, sast, risk_narrative, ...). Born tenant-aware (tenant_id, R9) so the
-- P5/E22 row-scoping sweep covers it with no backfill; reads are engagement-scoped today via the
-- tenant-scoped engagement gate (mirrors findings). The typed Claim is stored as its fail-closed
-- discriminated envelope (JSONB) – never free prose (golden rule 5). evidence_score + state move
-- ONLY via the analysis use case's verify/accept path (optimistic concurrency on version); the
-- proposing agent has no path to set them.
CREATE TABLE judgments (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    engagement_id  TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    capability     TEXT NOT NULL,
    subject_kind   TEXT NOT NULL,
    subject_id     TEXT NOT NULL,
    claim          JSONB NOT NULL,
    state          TEXT NOT NULL,
    evidence_score INTEGER NOT NULL DEFAULT 0,
    proposed_by    TEXT NOT NULL DEFAULT '',
    version        INTEGER NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_judgments_engagement ON judgments(engagement_id);
CREATE INDEX idx_judgments_subject ON judgments(engagement_id, subject_id);
CREATE INDEX idx_judgments_tenant ON judgments(tenant_id);

-- +goose Down
DROP TABLE IF EXISTS judgments;
