-- +goose Up
-- E3 findings workflow: a human assignee + an optimistic-concurrency version on
-- findings (Kanban/status edits check it to prevent lost updates), and a persisted
-- comment thread (the Phase 1 triage note was audit-only – comments are the
-- collaboration record, FR-B7).
ALTER TABLE findings ADD COLUMN assignee TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN version  INT  NOT NULL DEFAULT 1;

CREATE TABLE finding_comments (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author        TEXT NOT NULL,
    body          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_finding_comments_finding ON finding_comments(finding_id, created_at);

-- +goose Down
DROP TABLE finding_comments;
ALTER TABLE findings DROP COLUMN version;
ALTER TABLE findings DROP COLUMN assignee;
