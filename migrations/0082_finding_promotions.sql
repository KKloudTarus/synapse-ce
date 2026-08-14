-- +goose Up
-- Phase B1 (Task #9): promotion lifecycle persistence — the append-only record of
-- applied finding-priority changes plus the atomic CAS store that moves a finding's
-- priority and version in the same transaction as the event append.
--
-- 1) Backfill judgments.tenant_id from their engagement's tenant. Strict: fail
--    if engagement tenant is empty/missing or if an existing non-empty judgment
--    tenant conflicts with its engagement tenant. No fallback/default ownership.
--    Temporarily lifts FORCE RLS on engagements (restored atomically).
-- 2) Enable forced tenant RLS on judgments (previously unprotected since 0037).
-- 3) Add composite UNIQUE(tenant_id, id) on judgments so composite FKs from
--    finding_promotion_events can reference tenant-scoped parent keys.
-- 4) finding_promotion_events: append-only, RLS-protected, composite
--    tenant-scoped idempotency, complete metadata, RESTRICT FKs.
-- 5) Remove standalone SetPriority from the finding mutation surface.

-- 1. Backfill judgments.tenant_id from engagements. Strict: fail if any
--    judgment has no resolvable engagement or the engagement tenant is empty.
--    Fail if an existing non-empty judgment tenant conflicts with engagement.
--
--    Migrations run as the table owner. engagements already has FORCE RLS
--    (migration 0057/0066), so the backfill JOIN would see zero engagement
--    rows when app.current_tenant is unset. Temporarily lift FORCE on
--    engagements for this transaction; RLS remains ENABLED (non-owner roles
--    are still governed). Restore FORCE at the end of the same DO block so
--    any failure rolls back the entire goose transaction, restoring FORCE
--    automatically.
-- +goose StatementBegin
DO $$
BEGIN
    -- Lift FORCE so the migration-owner role can read all engagements.
    EXECUTE 'ALTER TABLE engagements NO FORCE ROW LEVEL SECURITY';

    -- Strict backfill: fail if any judgment is orphaned or has a tenant
    -- conflict with its engagement.
    PERFORM 1 FROM (
        SELECT j.id
          FROM judgments j
     LEFT JOIN engagements e ON j.engagement_id = e.id
         WHERE e.id IS NULL
            OR e.tenant_id IS NULL
            OR e.tenant_id = ''
         LIMIT 1
    ) bad;
    IF FOUND THEN
        RAISE EXCEPTION 'judgments tenant backfill: some judgments have no resolvable engagement or engagement has empty tenant';
    END IF;

    PERFORM 1 FROM (
        SELECT j.id
          FROM judgments j
          JOIN engagements e ON j.engagement_id = e.id
         WHERE j.tenant_id IS NOT NULL
           AND j.tenant_id != ''
           AND j.tenant_id != e.tenant_id
         LIMIT 1
    ) bad;
    IF FOUND THEN
        RAISE EXCEPTION 'judgments tenant backfill: some judgments have tenant_id conflicting with engagement tenant';
    END IF;

    UPDATE judgments j
       SET tenant_id = e.tenant_id
      FROM engagements e
     WHERE j.engagement_id = e.id
       AND (j.tenant_id IS NULL OR j.tenant_id = '');

    -- Restore FORCE RLS on engagements before this transaction commits.
    EXECUTE 'ALTER TABLE engagements FORCE ROW LEVEL SECURITY';
END $$;
-- +goose StatementEnd

-- 2. Enable forced tenant RLS on judgments (was unprotected since migration 0037).
CALL synapse_enable_tenant_rls('judgments');

-- 3. Add composite UNIQUE constraints on judgments so composite FKs from
--    finding_promotion_events can reference tenant-scoped parent keys.
--    judgments_tenant_id_unique supports the tenant-scoped (tenant_id, id)
--    FK path. judgments_tenant_engagement_id_unique adds engagement-level
--    ownership binding so the judgment FK also constrains engagement_id,
--    preventing a promotion from referencing a judgment that belongs to a
--    different engagement within the same tenant.
--    engagements already has engagements_tenant_id_unique from migration 0066.
--    findings already has findings_tenant_engagement_id_unique from migration 0066.
ALTER TABLE judgments ADD CONSTRAINT judgments_tenant_id_unique UNIQUE (tenant_id, id);
ALTER TABLE judgments ADD CONSTRAINT judgments_tenant_engagement_id_unique UNIQUE (tenant_id, engagement_id, id);

-- 4. The promotion events table. Append-only, tenant-scoped, complete metadata.
CREATE TABLE finding_promotion_events (
    id                     TEXT PRIMARY KEY,
    tenant_id              TEXT NOT NULL,
    engagement_id          TEXT NOT NULL,
    judgment_id            TEXT NOT NULL,
    finding_id             TEXT NOT NULL,
    finding_version        INTEGER NOT NULL,
    after_finding_version  INTEGER NOT NULL,
    rule                   TEXT NOT NULL,
    effect                 TEXT NOT NULL,
    before_priority        INTEGER NOT NULL,
    after_priority         INTEGER NOT NULL,
    inputs                 JSONB NOT NULL,
    fingerprint            TEXT NOT NULL,
    verdict_score          INTEGER NOT NULL DEFAULT 0,
    verdict_rationale      TEXT NOT NULL DEFAULT '',
    evidence_id            TEXT NOT NULL DEFAULT '',
    verifier               TEXT NOT NULL DEFAULT '',
    uncertainty            JSONB NOT NULL DEFAULT '[]',
    applied_by             TEXT NOT NULL DEFAULT '',
    applied_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Composite foreign keys using tenant-scoped parent unique constraints.
-- RESTRICT (not CASCADE): promotion history is append-only — deleting a parent
-- row that has promotion history must be explicitly blocked, not silently
-- cascade-destroyed. This follows the repository's append-only evidence/audit
-- precedent.
ALTER TABLE finding_promotion_events
    ADD CONSTRAINT fpe_engagement_fk
        FOREIGN KEY (tenant_id, engagement_id)
        REFERENCES engagements(tenant_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT fpe_finding_fk
        FOREIGN KEY (tenant_id, engagement_id, finding_id)
        REFERENCES findings(tenant_id, engagement_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT fpe_judgment_fk
        FOREIGN KEY (tenant_id, engagement_id, judgment_id)
        REFERENCES judgments(tenant_id, engagement_id, id) ON DELETE RESTRICT;

-- Tenant FK: enforce that the tenant exists.
ALTER TABLE finding_promotion_events
    ADD CONSTRAINT fpe_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);

-- Priority range constraints.
ALTER TABLE finding_promotion_events
    ADD CONSTRAINT fpe_finding_version_positive CHECK (finding_version >= 1),
    ADD CONSTRAINT fpe_after_version_positive CHECK (after_finding_version >= finding_version),
    ADD CONSTRAINT fpe_before_priority_range CHECK (before_priority >= 1 AND before_priority <= 5),
    ADD CONSTRAINT fpe_after_priority_range CHECK (after_priority >= 1 AND after_priority <= 5);

-- Composite tenant+judgment idempotency: a single judgment cannot produce
-- multiple promotion events under the same tenant.
CREATE UNIQUE INDEX fpe_judgment_uniq
    ON finding_promotion_events (tenant_id, judgment_id);

-- Composite tenant+fingerprint idempotency: the same claim digest cannot
-- appear twice under the same tenant.
CREATE UNIQUE INDEX fpe_fingerprint_uniq
    ON finding_promotion_events (tenant_id, fingerprint);

-- Query indexes for the ListByFinding / LatestByFinding read paths.
-- Includes engagement_id for tenant+engagement+finding scoping.
CREATE INDEX fpe_finding_idx
    ON finding_promotion_events (tenant_id, engagement_id, finding_id, applied_at, id);

CREATE INDEX fpe_engagement_idx
    ON finding_promotion_events (tenant_id, engagement_id);

-- RLS: tenant isolation at the database level.
CALL synapse_enable_tenant_rls('finding_promotion_events');

-- Append-only enforcement: block UPDATE / DELETE / TRUNCATE.
CREATE TRIGGER fpe_append_only
    BEFORE UPDATE OR DELETE ON finding_promotion_events
    FOR EACH ROW EXECUTE FUNCTION synapse_forbid_mutation();

CREATE TRIGGER fpe_no_truncate
    BEFORE TRUNCATE ON finding_promotion_events
    FOR EACH STATEMENT EXECUTE FUNCTION synapse_forbid_mutation();

-- +goose Down
-- Reverse 0082 additions in dependency order.

-- 1. Remove triggers from finding_promotion_events.
DROP TRIGGER IF EXISTS fpe_no_truncate ON finding_promotion_events;
DROP TRIGGER IF EXISTS fpe_append_only ON finding_promotion_events;

-- 2. Remove indexes.
DROP INDEX IF EXISTS fpe_engagement_idx;
DROP INDEX IF EXISTS fpe_finding_idx;
DROP INDEX IF EXISTS fpe_fingerprint_uniq;
DROP INDEX IF EXISTS fpe_judgment_uniq;

-- 3. Remove constraints added by 0082 (FKs and check constraints).
ALTER TABLE finding_promotion_events DROP CONSTRAINT IF EXISTS fpe_tenant_fk;
ALTER TABLE finding_promotion_events DROP CONSTRAINT IF EXISTS fpe_judgment_fk;
ALTER TABLE finding_promotion_events DROP CONSTRAINT IF EXISTS fpe_finding_fk;
ALTER TABLE finding_promotion_events DROP CONSTRAINT IF EXISTS fpe_engagement_fk;
ALTER TABLE finding_promotion_events DROP CONSTRAINT IF EXISTS fpe_finding_version_positive;
ALTER TABLE finding_promotion_events DROP CONSTRAINT IF EXISTS fpe_after_version_positive;
ALTER TABLE finding_promotion_events DROP CONSTRAINT IF EXISTS fpe_before_priority_range;
ALTER TABLE finding_promotion_events DROP CONSTRAINT IF EXISTS fpe_after_priority_range;

-- 4. Drop the table.
DROP TABLE IF EXISTS finding_promotion_events;

-- 5. Remove the judgments composite unique constraints added by 0082.
--    Drop engagement-scoped first (depends on tenant-scoped for the parent side
--    of the FK, though we already dropped fpe_judgment_fk above).
ALTER TABLE judgments DROP CONSTRAINT IF EXISTS judgments_tenant_engagement_id_unique;
ALTER TABLE judgments DROP CONSTRAINT IF EXISTS judgments_tenant_id_unique;

-- 6. Remove the judgments RLS policy and forced RLS added by 0082.
--    synapse_enable_tenant_rls creates a policy named "<table>_tenant_isolation".
--    We must drop the policy before disabling RLS, then un-FORCE it.
DROP POLICY IF EXISTS judgments_tenant_isolation ON judgments;
ALTER TABLE judgments NO FORCE ROW LEVEL SECURITY;
ALTER TABLE judgments DISABLE ROW LEVEL SECURITY;
