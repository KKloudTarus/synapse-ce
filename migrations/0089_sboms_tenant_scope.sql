-- +goose Up
-- Continuous vulnerability correlation reads persisted inventory outside the request that
-- created it. Give every inventory row an explicit tenant and enforce the ownership chain in
-- PostgreSQL so background workers cannot cross a tenant boundary accidentally.

UPDATE sboms s
SET tenant_id = e.tenant_id
FROM engagements e
WHERE s.engagement_id = e.id
  AND s.tenant_id IS DISTINCT FROM e.tenant_id;

ALTER TABLE sboms
  ADD CONSTRAINT sboms_tenant_id_unique UNIQUE (tenant_id, id);
ALTER TABLE sboms DROP CONSTRAINT sboms_engagement_id_fkey;
ALTER TABLE sboms
  ADD CONSTRAINT sboms_engagement_fk_tenant
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id)
  ON DELETE SET NULL (engagement_id);
CREATE INDEX idx_sboms_tenant_engagement_created
  ON sboms(tenant_id, engagement_id, created_at DESC, id DESC);

ALTER TABLE components ADD COLUMN tenant_id TEXT REFERENCES tenants(id);
UPDATE components c SET tenant_id = s.tenant_id FROM sboms s WHERE c.sbom_id = s.id;
ALTER TABLE components ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE components ADD CONSTRAINT components_tenant_id_unique UNIQUE (tenant_id, id);
ALTER TABLE components DROP CONSTRAINT components_sbom_id_fkey;
ALTER TABLE components
  ADD CONSTRAINT components_sbom_fk_tenant
  FOREIGN KEY (tenant_id, sbom_id) REFERENCES sboms(tenant_id, id) ON DELETE CASCADE;
CREATE INDEX idx_components_tenant_sbom ON components(tenant_id, sbom_id, id);

ALTER TABLE vulnerabilities ADD COLUMN tenant_id TEXT REFERENCES tenants(id);
UPDATE vulnerabilities v SET tenant_id = c.tenant_id FROM components c WHERE v.component_id = c.id;
ALTER TABLE vulnerabilities ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE vulnerabilities DROP CONSTRAINT vulnerabilities_component_id_fkey;
ALTER TABLE vulnerabilities
  ADD CONSTRAINT vulnerabilities_component_fk_tenant
  FOREIGN KEY (tenant_id, component_id) REFERENCES components(tenant_id, id) ON DELETE CASCADE;
CREATE INDEX idx_vulnerabilities_tenant_component ON vulnerabilities(tenant_id, component_id, id);

CALL synapse_enable_tenant_rls('sboms');
CALL synapse_enable_tenant_rls('components');
CALL synapse_enable_tenant_rls('vulnerabilities');

-- +goose Down
DROP POLICY vulnerabilities_tenant_isolation ON vulnerabilities;
ALTER TABLE vulnerabilities NO FORCE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities DISABLE ROW LEVEL SECURITY;
DROP POLICY components_tenant_isolation ON components;
ALTER TABLE components NO FORCE ROW LEVEL SECURITY;
ALTER TABLE components DISABLE ROW LEVEL SECURITY;
DROP POLICY sboms_tenant_isolation ON sboms;
ALTER TABLE sboms NO FORCE ROW LEVEL SECURITY;
ALTER TABLE sboms DISABLE ROW LEVEL SECURITY;

DROP INDEX idx_vulnerabilities_tenant_component;
ALTER TABLE vulnerabilities DROP CONSTRAINT vulnerabilities_component_fk_tenant;
ALTER TABLE vulnerabilities
  ADD CONSTRAINT vulnerabilities_component_id_fkey
  FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE;
ALTER TABLE vulnerabilities DROP COLUMN tenant_id;

DROP INDEX idx_components_tenant_sbom;
ALTER TABLE components DROP CONSTRAINT components_sbom_fk_tenant;
ALTER TABLE components DROP CONSTRAINT components_tenant_id_unique;
ALTER TABLE components
  ADD CONSTRAINT components_sbom_id_fkey
  FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE;
ALTER TABLE components DROP COLUMN tenant_id;

DROP INDEX idx_sboms_tenant_engagement_created;
ALTER TABLE sboms DROP CONSTRAINT sboms_engagement_fk_tenant;
ALTER TABLE sboms DROP CONSTRAINT sboms_tenant_id_unique;
ALTER TABLE sboms
  ADD CONSTRAINT sboms_engagement_id_fkey
  FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL;
