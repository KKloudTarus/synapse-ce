-- +goose Up
-- E6 retest tracking (FR-B6): an append-only history of re-tests on a finding (who
-- re-tested, the outcome, a note). The outcome also moves the finding's status
-- (handled in the use case). No tenant FK – single-tenant for now (matches audit_log).
CREATE TABLE finding_retests (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL DEFAULT '',
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    outcome       TEXT NOT NULL,
    note          TEXT NOT NULL DEFAULT '',
    tester        TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_finding_retests_finding ON finding_retests(finding_id, created_at);

-- +goose Down
DROP TABLE finding_retests;
