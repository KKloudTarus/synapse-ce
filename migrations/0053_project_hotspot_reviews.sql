-- +goose Up
CREATE TABLE project_hotspot_review_events (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hotspot_id       TEXT NOT NULL REFERENCES project_hotspots(id) ON DELETE CASCADE,
    from_status      TEXT NOT NULL,
    to_status        TEXT NOT NULL,
    actor            TEXT NOT NULL,
    rationale        TEXT NOT NULL,
    previous_version INTEGER NOT NULL,
    version          INTEGER NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,

    UNIQUE (hotspot_id, version),
    CHECK (from_status IN ('to_review', 'acknowledged', 'fixed', 'safe')),
    CHECK (to_status IN ('to_review', 'acknowledged', 'fixed', 'safe')),
    CHECK (from_status <> to_status),
    CHECK (version = previous_version + 1),
    CHECK (length(actor) > 0),
    CHECK (length(rationale) > 0)
);

CREATE INDEX idx_project_hotspot_review_events_version
    ON project_hotspot_review_events (tenant_id, project_id, hotspot_id, version ASC);

CREATE TABLE project_analysis_hotspots (
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    analysis_id       TEXT NOT NULL REFERENCES project_analyses(id) ON DELETE CASCADE,
    hotspot_id        TEXT NOT NULL REFERENCES project_hotspots(id) ON DELETE CASCADE,
    is_new             BOOLEAN NOT NULL,
    status_at_analysis TEXT NOT NULL,
    version_at_analysis INTEGER NOT NULL,

    PRIMARY KEY (analysis_id, hotspot_id),
    CHECK (status_at_analysis IN ('to_review', 'acknowledged', 'fixed', 'safe')),
    CHECK (version_at_analysis >= 1)
);

CREATE INDEX idx_project_analysis_hotspots_new
    ON project_analysis_hotspots (tenant_id, project_id, analysis_id, is_new);

CREATE INDEX idx_project_analysis_hotspots_hotspot
    ON project_analysis_hotspots (tenant_id, project_id, hotspot_id);

-- +goose Down
DROP TABLE project_analysis_hotspots;
DROP TABLE project_hotspot_review_events;
