-- +goose Up
-- Attack-path bindings may target either governed findings or durable SARIF imports.
-- Keep both references as native foreign keys: a polymorphic to_id alone cannot prevent
-- dangling rows or prove an imported target belongs to the binding's tenant and engagement.
ALTER TABLE imported_findings
    ADD CONSTRAINT imported_findings_id_tenant_engagement_unique UNIQUE (id, tenant_id, engagement_id);

ALTER TABLE attack_path_edges
    ADD COLUMN target_kind TEXT,
    ADD COLUMN canonical_finding_id TEXT,
    ADD COLUMN imported_finding_id TEXT;
UPDATE attack_path_edges
    SET target_kind = 'canonical', canonical_finding_id = to_id;
ALTER TABLE attack_path_edges
    ALTER COLUMN target_kind SET NOT NULL;
ALTER TABLE attack_path_edges
    DROP CONSTRAINT attack_path_edges_to_id_engagement_id_fkey,
    DROP CONSTRAINT attack_path_edges_pkey,
    ADD CONSTRAINT attack_path_edges_target_check CHECK (
        (target_kind = 'canonical' AND canonical_finding_id = to_id AND imported_finding_id IS NULL) OR
        (target_kind = 'imported' AND imported_finding_id = to_id AND canonical_finding_id IS NULL)
    ),
    ADD PRIMARY KEY (tenant_id, engagement_id, from_kind, from_id, to_kind, to_id, target_kind, kind, producer, provenance),
    ADD CONSTRAINT attack_path_edges_canonical_finding_fkey
        FOREIGN KEY (canonical_finding_id, engagement_id)
        REFERENCES findings(id, engagement_id) ON DELETE CASCADE,
    ADD CONSTRAINT attack_path_edges_imported_finding_fkey
        FOREIGN KEY (imported_finding_id, tenant_id, engagement_id)
        REFERENCES imported_findings(id, tenant_id, engagement_id) ON DELETE CASCADE;

-- +goose Down
DELETE FROM attack_path_edges WHERE target_kind = 'imported';
ALTER TABLE attack_path_edges
    DROP CONSTRAINT attack_path_edges_imported_finding_fkey,
    DROP CONSTRAINT attack_path_edges_canonical_finding_fkey,
    DROP CONSTRAINT attack_path_edges_target_check,
    DROP CONSTRAINT attack_path_edges_pkey,
    ADD PRIMARY KEY (tenant_id, engagement_id, from_kind, from_id, to_kind, to_id, kind, producer, provenance),
    ADD FOREIGN KEY (to_id, engagement_id) REFERENCES findings(id, engagement_id) ON DELETE CASCADE,
    DROP COLUMN imported_finding_id,
    DROP COLUMN canonical_finding_id,
    DROP COLUMN target_kind;
ALTER TABLE imported_findings DROP CONSTRAINT imported_findings_id_tenant_engagement_unique;
