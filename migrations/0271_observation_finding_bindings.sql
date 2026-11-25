-- +goose Up
-- Approved observation-to-finding bindings (#1184).
--
-- An imported finding's finding_id is set by the deduplicator when an external result lands on the same
-- file and line as a first-party finding. That is a CANDIDATE. This table holds the other thing: a
-- person's decision that the two describe one issue, with who decided it, why, and which observation row
-- they were looking at.
--
-- Identity is (scope, external_identity), never the observation row id. Re-importing a report mints new
-- imported_findings rows, and a decision a person made has to survive that.
CREATE TABLE observation_finding_bindings (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    engagement_id     TEXT NOT NULL,
    -- Both halves of the identity are bounded because they sit in a btree index, whose tuples cannot
    -- exceed 2704 bytes. The SARIF reader caps a rule id at 512 bytes and a path at 4096, so an
    -- unbounded identity reaches ~4.6 KB and the insert fails with a 54000 the caller cannot act on.
    -- ImportedFinding.BindingExternalIdentity digests anything longer, so these are a floor under that.
    scope             TEXT NOT NULL CHECK (scope <> '' AND octet_length(scope) <= 512),
    external_identity TEXT NOT NULL CHECK (external_identity <> '' AND octet_length(external_identity) <= 1024),
    finding_id        TEXT NOT NULL CHECK (finding_id <> ''),
    observation_id    TEXT NOT NULL CHECK (observation_id <> ''),
    version           INTEGER NOT NULL CHECK (version >= 1),
    decided_by        TEXT NOT NULL CHECK (decided_by <> ''),
    reason            TEXT NOT NULL CHECK (reason <> '' AND octet_length(reason) <= 2000),
    decided_at        TIMESTAMPTZ NOT NULL,
    superseded_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (superseded_at IS NULL OR superseded_at >= decided_at),

    -- Cross-tenant reference protection. The composite keys carry the tenant and the engagement into the
    -- reference, so a binding cannot point at another tenant's finding or at an observation from a
    -- different engagement even if a caller supplies the ids. A plain finding_id REFERENCES findings(id)
    -- would accept both.
    CONSTRAINT observation_finding_bindings_finding_fk
        FOREIGN KEY (tenant_id, engagement_id, finding_id)
        REFERENCES findings(tenant_id, engagement_id, id) ON DELETE CASCADE,
    -- RESTRICT, not CASCADE. The identity a binding is keyed on was chosen to outlive the row, because
    -- re-importing a report mints new observation rows. Letting a row deletion take the decision with it
    -- would undo that on the one path where it matters: the lineage and the version in force would both
    -- vanish, and the next adopt would start again at version 1 with nothing to show a decision was ever
    -- made. Deleting an engagement still works, because that cascades through findings to the binding,
    -- and this constraint only guards deletion of the observation itself.
    CONSTRAINT observation_finding_bindings_observation_fk
        FOREIGN KEY (observation_id, tenant_id, engagement_id)
        REFERENCES imported_findings(id, tenant_id, engagement_id) ON DELETE RESTRICT
);

-- One binding in force per scoped identity. The partial index is what makes concurrent adoption resolve
-- to a single winner in the database rather than in whichever process got there first: superseded
-- versions are kept, so a full unique index would forbid the history this table exists to carry.
CREATE UNIQUE INDEX observation_finding_bindings_current ON observation_finding_bindings
    (tenant_id, engagement_id, scope, external_identity) WHERE superseded_at IS NULL;

-- The lineage read lists a whole engagement and the identity lookups are all partial-index lookups on
-- the versions in force, so this index serves both: it is the narrow one the planner picks for a full
-- engagement scan, and it supports the finding foreign key.
CREATE INDEX observation_finding_bindings_finding ON observation_finding_bindings
    (tenant_id, engagement_id, finding_id);

-- The observation foreign key needs a leading observation_id, or every deletion of an imported finding
-- scans the engagement's bindings to prove none point at it. Measured on 101,000 bindings in one
-- engagement: 49 ms per deleted observation without this index, against 0.07 ms with one.
CREATE INDEX observation_finding_bindings_observation ON observation_finding_bindings
    (observation_id, tenant_id, engagement_id);

CALL synapse_enable_tenant_rls('observation_finding_bindings');

-- A decision is append-only in place. The single permitted mutation is retiring a current version, which
-- is what Supersede does inside the same transaction that inserts its replacement. Without this guard a
-- caller could rewrite the actor or the reason on a decision already made.
--
-- The trigger deliberately does not cover DELETE. A BEFORE DELETE trigger also fires for a cascade, so
-- guarding it here would make an engagement with any binding impossible to delete. Direct deletion by the
-- runtime role is revoked instead, in the grant pass in persistence/postgres/db.go, which leaves the
-- cascade working because a referential action runs as the table owner. The durable record of the
-- decision itself is the hash-chained audit_log entry, which survives either way.
-- +goose StatementBegin
CREATE FUNCTION synapse_guard_observation_binding_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.engagement_id IS DISTINCT FROM OLD.engagement_id
       OR NEW.scope IS DISTINCT FROM OLD.scope
       OR NEW.external_identity IS DISTINCT FROM OLD.external_identity
       OR NEW.finding_id IS DISTINCT FROM OLD.finding_id
       OR NEW.observation_id IS DISTINCT FROM OLD.observation_id
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.decided_by IS DISTINCT FROM OLD.decided_by
       OR NEW.reason IS DISTINCT FROM OLD.reason
       OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'observation binding decisions are immutable';
    END IF;

    IF OLD.superseded_at IS NOT NULL THEN
        RAISE EXCEPTION 'observation binding version % is already superseded', OLD.version;
    END IF;
    IF NEW.superseded_at IS NULL THEN
        RAISE EXCEPTION 'the only permitted observation binding update is retiring a current version';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER observation_finding_bindings_guard_update
    BEFORE UPDATE ON observation_finding_bindings
    FOR EACH ROW EXECUTE FUNCTION synapse_guard_observation_binding_update();

-- +goose Down
DROP TRIGGER IF EXISTS observation_finding_bindings_guard_update ON observation_finding_bindings;
DROP FUNCTION IF EXISTS synapse_guard_observation_binding_update();
DROP TABLE observation_finding_bindings;
