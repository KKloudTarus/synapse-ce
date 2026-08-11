-- +goose Up
-- Detection ledger projection (issue #423). A detection is sealed into the SAME hash-chained evidence
-- spine as findings and judgments (kind = 'detection'); this table is the QUERYABLE PROJECTION over
-- those chain links — it is not a second chain. Every row references its evidence link (so it is
-- attributable and defensible) and the asset it was observed on (so it joins the asset risk story).
--
-- Retention lives here: the evidence chain link is PERMANENT (append-only), but this projection row is
-- retention-bounded and can be expired by an AUDITED action. Deleting a projection row never touches the
-- chain, so the tamper-evident ledger is intact even after an operational row is aged out.
CREATE TABLE detections (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    id            TEXT NOT NULL,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    asset_id      TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    rule_version  INT  NOT NULL,
    class         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    host_id       TEXT NOT NULL,
    observed_at   TIMESTAMPTZ NOT NULL,
    -- The sealed chain link this detection is. A detection cannot exist without its evidence, so the FK
    -- is NOT NULL and points at the real chain row.
    evidence_id   TEXT NOT NULL REFERENCES evidence(id),
    batch_seq     BIGINT NOT NULL,
    detection     JSONB  NOT NULL,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL = never expires. A set value is enforced only by an audited expiry action, never a silent job.
    expires_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX idx_detections_engagement ON detections(tenant_id, engagement_id, recorded_at);
CREATE INDEX idx_detections_agent_seq  ON detections(tenant_id, agent_id, batch_seq);

-- Incident rollup: repeated detections of the same rule on the same asset, folded into an incident-level
-- view. It is a VIEW — the individual attributable detections remain the ledger underneath, and
-- array_agg(id) lets an auditor descend from an incident to them. security_invoker makes the base
-- table's RLS apply to the QUERYING tenant, so the rollup is tenant-scoped exactly like the table.
CREATE VIEW detection_incidents
    WITH (security_invoker = true) AS
SELECT tenant_id,
       engagement_id,
       asset_id,
       rule_id,
       count(*)                  AS detection_count,
       -- Severity is a LABEL, so a plain max() would be alphabetical ('low' > 'high' > 'critical') and
       -- under-report risk. Rank by an explicit ordinal and map the highest rank back to its label.
       (ARRAY['info','low','medium','high','critical'])[
           max(array_position(ARRAY['info','low','medium','high','critical'], severity))
       ]                         AS worst_severity,
       min(observed_at)          AS first_observed,
       max(observed_at)          AS last_observed,
       array_agg(id ORDER BY id) AS detection_ids
FROM detections
GROUP BY tenant_id, engagement_id, asset_id, rule_id;

CALL synapse_enable_tenant_rls('detections');

-- +goose Down
DROP VIEW IF EXISTS detection_incidents;
DROP TABLE detections;
