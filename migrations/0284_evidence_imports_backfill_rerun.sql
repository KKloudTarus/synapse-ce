-- +goose Up
-- Rerun of the 0280 backfill (#1734). 0280 marked the evidence links of every imported engagement once,
-- from the engagement.imported audit records. A v0.3.0 binary that served an import after 0280 ran did not
-- write the marker, because it did not know the table. This release deploys after every v0.3.0 binary is
-- gone, so running the same block again marks those imports. The block is idempotent: ON CONFLICT DO
-- NOTHING on the marker's primary key, and imports already marked produce no row. The sealed finding id
-- (0283) stays NULL for these rows: before 0283 no finding-linked link could be imported, so there is
-- nothing to record. Imports recorded only on the legacy global audit chain stay unmarked, as in 0280;
-- docs/guide/backup-restore-upgrade.md gives the maintenance query for them.
-- +goose StatementBegin
DO $$
DECLARE
    t TEXT;
    v_marked BIGINT := 0;
    v_rows BIGINT;
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
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_marked := v_marked + v_rows;
    END LOOP;
    PERFORM set_config('app.current_tenant', '', true);
    IF v_marked > 0 THEN
        RAISE NOTICE 'migration 0284: marked % imported evidence links the 0280 backfill did not see', v_marked;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- The markers this rerun added are indistinguishable from 0280's and are append-only; nothing to undo.
SELECT 1;
