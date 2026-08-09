-- +goose Up
ALTER TABLE attack_path_edges ADD COLUMN producer TEXT;
UPDATE attack_path_edges SET producer = provenance WHERE producer IS NULL;
ALTER TABLE attack_path_edges ALTER COLUMN producer SET NOT NULL;
ALTER TABLE attack_path_edges
    DROP CONSTRAINT attack_path_edges_pkey,
    ADD PRIMARY KEY (tenant_id, engagement_id, from_kind, from_id, to_kind, to_id, kind, producer, provenance),
    ADD CONSTRAINT attack_path_edges_producer_check CHECK (producer <> '');
CREATE INDEX attack_path_edges_tenant_producer ON attack_path_edges (tenant_id, engagement_id, producer);

-- +goose Down
DROP INDEX attack_path_edges_tenant_producer;
DELETE FROM attack_path_edges a
USING attack_path_edges b
WHERE a.tenant_id = b.tenant_id
  AND a.engagement_id = b.engagement_id
  AND a.from_kind = b.from_kind
  AND a.from_id = b.from_id
  AND a.to_kind = b.to_kind
  AND a.to_id = b.to_id
  AND a.kind = b.kind
  AND a.provenance = b.provenance
  AND a.producer > b.producer;
ALTER TABLE attack_path_edges
    DROP CONSTRAINT attack_path_edges_producer_check,
    DROP CONSTRAINT attack_path_edges_pkey,
    ADD PRIMARY KEY (tenant_id, engagement_id, from_kind, from_id, to_kind, to_id, kind, provenance),
    DROP COLUMN producer;
