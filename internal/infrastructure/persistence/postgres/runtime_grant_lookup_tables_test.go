package postgres

import (
	"context"
	"testing"
)

// globalLookupTables are tenant-routing tables with no tenant column of their own, so RLS cannot
// carry them. Their migrations revoke them from PUBLIC and route the runtime role through a
// SECURITY DEFINER function that takes an exact key. GrantRuntimePrivileges then runs
// GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public, which grants them to the
// role by name, and a REVOKE FROM PUBLIC does not undo that. Each one needs its own REVOKE.
var globalLookupTables = []struct {
	table  string
	reason string
}{
	{
		table:  "scan_run_engagement_tenants",
		reason: "the engagement-to-tenant map every scan run is stamped from (migration 0144)",
	},
	{
		table:  "identity_recovery_activation_routes",
		reason: "every recovery secret digest with its tenant and expiry (migration 0211)",
	},
}

func TestRuntimeRoleCannotReachGlobalLookupTablesDirectly(t *testing.T) {
	fixture := newRLS817Fixture(t)
	ctx := context.Background()
	for _, subject := range globalLookupTables {
		for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			var granted bool
			if err := fixture.owner.QueryRow(ctx,
				"SELECT has_table_privilege($1, $2, $3)", rls817Role, subject.table, privilege,
			).Scan(&granted); err != nil {
				t.Fatalf("read %s privilege on %s: %v", privilege, subject.table, err)
			}
			if granted {
				t.Errorf("the runtime role holds %s on %s, which is %s; it must go through the SECURITY DEFINER locator instead",
					privilege, subject.table, subject.reason)
			}
		}
	}
}
