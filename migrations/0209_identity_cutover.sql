-- +goose Up
-- Durable authority ledger for the identity cutover. A flag can select an enabled request path,
-- but it cannot restore legacy authority after a declaration.
CREATE TABLE identity_cutover_ledger (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action TEXT NOT NULL CHECK (action IN ('prepared','declared','contracted','aborted')),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    policy_version INT NOT NULL CHECK (policy_version > 0),
    shadow_report_id TEXT,
    old_writer_generation TEXT,
    old_writer_count INT NOT NULL DEFAULT 0 CHECK (old_writer_count >= 0),
    migration_version INT NOT NULL DEFAULT 209 CHECK (migration_version >= 209),
    created_at TIMESTAMPTZ NOT NULL
    -- Prepared and aborted are append-only attempts; only terminal transitions are unique.
);
CALL synapse_enable_tenant_rls('identity_cutover_ledger');
CREATE UNIQUE INDEX identity_cutover_ledger_declared_once ON identity_cutover_ledger(tenant_id) WHERE action='declared';
CREATE UNIQUE INDEX identity_cutover_ledger_contracted_once ON identity_cutover_ledger(tenant_id) WHERE action='contracted';
CREATE TRIGGER identity_cutover_ledger_append_only BEFORE UPDATE OR DELETE ON identity_cutover_ledger
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_append_only();

CREATE TABLE identity_cutover_writer_evidence (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    generation TEXT NOT NULL CHECK (length(generation) BETWEEN 1 AND 256),
    active_writers INT NOT NULL CHECK (active_writers >= 0),
    observed_at TIMESTAMPTZ NOT NULL,
    observer TEXT NOT NULL CHECK (length(observer) BETWEEN 1 AND 256)
);
CALL synapse_enable_tenant_rls('identity_cutover_writer_evidence');
CREATE TRIGGER identity_cutover_writer_evidence_append_only BEFORE UPDATE OR DELETE ON identity_cutover_writer_evidence
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_append_only();

CREATE TABLE identity_cutover_writer_heartbeats (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) CHECK (tenant_id <> ''),
    instance_id TEXT NOT NULL CHECK (length(instance_id) BETWEEN 1 AND 256),
    generation TEXT NOT NULL CHECK (length(generation) BETWEEN 1 AND 256),
    seen_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, instance_id)
);
CALL synapse_enable_tenant_rls('identity_cutover_writer_heartbeats');

-- A terminal declaration is enforced at the data boundary. The legacy/shadow policy guard from
-- 0206 remains the compatibility guard; this trigger prevents a direct SQL phase reversal.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_guard_declared_cutover()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $cutover_guard$
BEGIN
    IF OLD.cutover_phase = 'declared' AND NEW.cutover_phase <> 'declared' THEN
        RAISE EXCEPTION 'declared identity cutover is terminal' USING ERRCODE = 'SYN03';
    END IF;
    IF NEW.cutover_phase = 'declared' AND NOT EXISTS (
        SELECT 1 FROM public.identity_cutover_ledger l
        WHERE l.tenant_id=NEW.tenant_id AND l.action='declared'
    ) THEN
        RAISE EXCEPTION 'declaration requires cutover evidence ledger' USING ERRCODE = 'SYN03';
    END IF;
    RETURN NEW;
END;
$cutover_guard$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_guard_declared_cutover() FROM PUBLIC;
CREATE TRIGGER identity_policies_declared_cutover_guard BEFORE UPDATE ON identity_policies
    FOR EACH ROW EXECUTE FUNCTION synapse_identity_guard_declared_cutover();

-- +goose Down
-- Evidence makes this migration intentionally forward-only once an operator uses it.
ALTER TABLE identity_cutover_ledger NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_cutover_writer_evidence NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM identity_cutover_ledger) OR EXISTS (SELECT 1 FROM identity_cutover_writer_evidence) THEN
        RAISE EXCEPTION 'identity cutover evidence exists; forward-fix or archive it before reverting migration 0209';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS identity_policies_declared_cutover_guard ON identity_policies;
DROP FUNCTION IF EXISTS synapse_identity_guard_declared_cutover();
DROP TABLE IF EXISTS identity_cutover_writer_heartbeats;
DROP TABLE IF EXISTS identity_cutover_writer_evidence;
DROP TABLE IF EXISTS identity_cutover_ledger;
