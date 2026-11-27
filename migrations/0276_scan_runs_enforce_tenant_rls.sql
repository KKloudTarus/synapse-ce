-- +goose Up
-- Contract release for scan_runs (#1697), step two of two. A file of its own because goose runs each
-- file in one transaction: validating the check here holds only SHARE UPDATE EXCLUSIVE, so scan writes
-- continue while it reads the table, and SET NOT NULL then skips its own scan because a validated check
-- already proves the column holds no NULL.
--
-- The order matters. Row-level security is enabled last: a check validated after forced RLS would be
-- validated by an owner that sees no rows, and would pass having tested nothing.
SET LOCAL lock_timeout = '5s';
ALTER TABLE scan_runs VALIDATE CONSTRAINT scan_runs_tenant_id_present;
ALTER TABLE scan_runs ALTER COLUMN tenant_id SET NOT NULL;
CALL synapse_enable_tenant_rls('scan_runs');

-- +goose Down
DROP POLICY IF EXISTS scan_runs_tenant_isolation ON scan_runs;
ALTER TABLE scan_runs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_runs DISABLE ROW LEVEL SECURITY;
ALTER TABLE scan_runs ALTER COLUMN tenant_id DROP NOT NULL;
