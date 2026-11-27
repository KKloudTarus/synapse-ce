-- +goose Up
-- Artifact blobs are content-addressed in one namespace shared by every tenant, and an artifact is
-- served to an engagement whose chain references its sha256. An imported bundle carries its links but no
-- blob bytes, and its links are chosen by whoever built the bundle. A link that names another tenant's
-- artifact sha would make the blob store serve that artifact to the importing tenant. This table records
-- which links arrived by import, so the evidence service serves an artifact only through a link sealed
-- on this instance. It is separate from evidence because evidence is append-only: the marker is added
-- without updating a sealed row, and it is not part of any link's hash.
SET LOCAL lock_timeout = '5s';
CREATE TABLE evidence_imports (
    tenant_id     TEXT NOT NULL CHECK (tenant_id <> ''),
    engagement_id TEXT NOT NULL,
    evidence_id   TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, evidence_id)
);
CREATE INDEX idx_evidence_imports_engagement ON evidence_imports (tenant_id, engagement_id);
CALL synapse_enable_tenant_rls('evidence_imports');

-- Backfill the links of engagements imported before this release. An import records
-- engagement.imported on its tenant's audit chain with the number of links it carried, and an imported
-- chain is appended before any native link, so the first evidence_links links of the engagement by seq
-- are the imported ones. Both tables force row-level security, so the backfill binds each tenant in
-- turn. Imports recorded only on the legacy global audit chain are not visible here and stay unmarked.
-- +goose StatementBegin
DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN SELECT id FROM tenants WHERE id <> '' LOOP
        PERFORM set_config('app.current_tenant', t, true);
        INSERT INTO evidence_imports (tenant_id, engagement_id, evidence_id)
        SELECT e.tenant_id, e.engagement_id, e.id
          FROM (SELECT id, tenant_id, engagement_id,
                       row_number() OVER (PARTITION BY engagement_id ORDER BY seq) AS rn
                  FROM evidence) e
          JOIN (SELECT target,
                       max(CASE WHEN metadata->>'evidence_links' ~ '^[0-9]{1,9}$'
                                THEN (metadata->>'evidence_links')::INT ELSE 0 END) AS links
                  FROM audit_log
                 WHERE action = 'engagement.imported'
                 GROUP BY target) a ON a.target = e.engagement_id
         WHERE e.rn <= a.links
        ON CONFLICT DO NOTHING;
    END LOOP;
    PERFORM set_config('app.current_tenant', '', true);
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS evidence_imports;
