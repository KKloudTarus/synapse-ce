-- +goose Up
-- A0.5 (#610): the detection ledger seals each detection into the evidence chain idempotently per
-- (engagement, detection id) — see detectledger.SealOnce. The projection's uniqueness key must match that
-- namespace, or the two idempotency scopes disagree: with the original PRIMARY KEY (tenant_id, id), the
-- SAME detection id delivered under two different engagements seals two distinct (correct) chain links but
-- collides here on the second engagement's row — ON CONFLICT (tenant_id, id) DO NOTHING silently drops it,
-- orphaning a chain link and leaving HasDetection(eng-2, id) false forever (the retry never converges).
-- Widen the key to (tenant_id, engagement_id, id) so a distinct-engagement detection is a distinct row.
-- Safe as a plain PK swap: the ingest write path is not wired yet (only the read surface is), so the table
-- is empty in every deployment; no row can violate the widened key.
ALTER TABLE detections DROP CONSTRAINT detections_pkey;
ALTER TABLE detections ADD PRIMARY KEY (tenant_id, engagement_id, id);

-- +goose Down
ALTER TABLE detections DROP CONSTRAINT detections_pkey;
ALTER TABLE detections ADD PRIMARY KEY (tenant_id, id);
