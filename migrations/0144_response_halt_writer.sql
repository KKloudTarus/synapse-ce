-- +goose Up
-- #680 isolate the only response-halt mutation capability from the ordinary runtime role.
-- Roles are provisioned externally as NOINHERIT/NOSUPERUSER/NOBYPASSRLS identities; this migration
-- grants only table rights after the composition root has supplied their names from DSNs.
DROP POLICY IF EXISTS response_halt_fences_tenant_isolation ON response_halt_fences;
CREATE POLICY response_halt_fences_tenant_select ON response_halt_fences FOR SELECT USING (tenant_id = synapse_current_tenant());
CREATE POLICY response_halt_fences_tenant_insert ON response_halt_fences FOR INSERT WITH CHECK (tenant_id = synapse_current_tenant());
CREATE POLICY response_halt_fences_tenant_update ON response_halt_fences FOR UPDATE USING (tenant_id = synapse_current_tenant()) WITH CHECK (tenant_id = synapse_current_tenant());

-- Runtime grants are deliberately broad for existing tables; remove halt manufacture after them.
-- synapse-migrate applies the exact grants to the configured role identities after migration.

-- +goose Down
DROP POLICY IF EXISTS response_halt_fences_tenant_update ON response_halt_fences;
DROP POLICY IF EXISTS response_halt_fences_tenant_insert ON response_halt_fences;
DROP POLICY IF EXISTS response_halt_fences_tenant_select ON response_halt_fences;
CREATE POLICY response_halt_fences_tenant_isolation ON response_halt_fences
    USING (tenant_id = synapse_current_tenant()) WITH CHECK (tenant_id = synapse_current_tenant());
