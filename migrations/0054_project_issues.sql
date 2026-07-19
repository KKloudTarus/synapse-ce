-- +goose Up
CREATE TABLE project_issues (
    id                     TEXT PRIMARY KEY,
    tenant_id              TEXT NOT NULL REFERENCES tenants(id),
    project_id             TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    issue_key              TEXT NOT NULL,
    finding_identity       TEXT NOT NULL,
    rule_key               TEXT NOT NULL,
    issue_type             TEXT NOT NULL,
    title                  TEXT NOT NULL,
    description            TEXT NOT NULL,
    severity               TEXT NOT NULL,
    finding_kind           TEXT NOT NULL,
    cwe                    TEXT NOT NULL DEFAULT '',
    language               TEXT NOT NULL DEFAULT '',
    file                   TEXT NOT NULL DEFAULT '',
    location               TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL CHECK (status IN ('open', 'accepted', 'false_positive', 'wont_fix')),
    version                INTEGER NOT NULL CHECK (version >= 1),
    is_new                 BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen_analysis_id TEXT NOT NULL,
    last_seen_analysis_id  TEXT NOT NULL,
    first_seen_at          TIMESTAMPTZ NOT NULL,
    last_seen_at           TIMESTAMPTZ NOT NULL,
    last_reviewed_by       TEXT NOT NULL DEFAULT '',
    last_reviewed_at       TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, project_id, issue_key)
);

CREATE INDEX idx_project_issues_tenant_project_status
    ON project_issues (tenant_id, project_id, status);
CREATE INDEX idx_project_issues_tenant_project_type
    ON project_issues (tenant_id, project_id, issue_type);
CREATE INDEX idx_project_issues_tenant_project_rule
    ON project_issues (tenant_id, project_id, rule_key);
CREATE INDEX idx_project_issues_tenant_project_seen
    ON project_issues (tenant_id, project_id, last_seen_at DESC, id COLLATE "C" DESC);

CREATE TABLE project_issue_review_events (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    issue_id         TEXT NOT NULL REFERENCES project_issues(id) ON DELETE CASCADE,
    from_status      TEXT NOT NULL,
    to_status        TEXT NOT NULL,
    actor            TEXT NOT NULL,
    rationale        TEXT NOT NULL,
    previous_version INTEGER NOT NULL,
    version          INTEGER NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,

    UNIQUE (issue_id, version),
    CHECK (from_status IN ('open', 'accepted', 'false_positive', 'wont_fix')),
    CHECK (to_status IN ('open', 'accepted', 'false_positive', 'wont_fix')),
    CHECK (from_status <> to_status),
    CHECK (version = previous_version + 1),
    CHECK (length(actor) > 0),
    CHECK (length(rationale) > 0)
);

CREATE INDEX idx_project_issue_review_events_version
    ON project_issue_review_events (tenant_id, project_id, issue_id, version ASC);

-- +goose Down
DROP TABLE project_issue_review_events;
DROP TABLE project_issues;
