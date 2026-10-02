package postgres

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

// usersConsumer records how one reference to the legacy users table is carried through identity
// migration. users stays the writer of record, and every stable actor ID stays users.id.
type usersConsumer struct {
	parent   string // referenced users key
	decision string
}

const (
	decisionLegacyUserID = "unchanged: resolves through membership legacy_user_id; a B-tenant member gets a tenant-local users row, never a second row with the same global users.id"
	decisionOIDC         = "unchanged: approved links import as identity_authenticators; sessions stay on the legacy BFF until cutover"
	decisionIdentity     = "new identity row pinned to its tenant-local legacy user"
)

// usersConsumers is every foreign key into users, keyed "table(columns)". The test fails when a
// migration adds, drops or retargets one without updating this table.
var usersConsumers = map[string]usersConsumer{
	"ownership_memberships(tenant_id,user_id)":              {"ownership_tenant_id,id", decisionLegacyUserID},
	"ownership_mappings(tenant_id,suggested_user_id)":       {"ownership_tenant_id,id", decisionLegacyUserID},
	"ownership_assignments(tenant_id,assignee_id)":          {"ownership_tenant_id,id", decisionLegacyUserID},
	"ownership_bulk_requests(tenant_id,actor_id)":           {"ownership_tenant_id,id", decisionLegacyUserID},
	"ownership_run_requests(tenant_id,actor_id)":            {"ownership_tenant_id,id", decisionLegacyUserID},
	"user_contacts(tenant_id,user_id)":                      {"ownership_tenant_id,id", decisionLegacyUserID + "; contact source/source_key provenance is not rewritten"},
	"user_contact_verification_requests(tenant_id,user_id)": {"ownership_tenant_id,id", decisionLegacyUserID},
	"findings(tenant_id,assignee_user_id)":                  {"ownership_tenant_id,id", decisionLegacyUserID + "; the assignee bridge trigger resolves the tenant-local id"},
	"user_notifications(tenant_id,user_id)":                 {"ownership_tenant_id,id", decisionLegacyUserID},
	"user_notification_preferences(tenant_id,user_id)":      {"ownership_tenant_id,id", decisionLegacyUserID},
	"oidc_external_identities(tenant_id,user_id)":           {"tenant_id,id", decisionOIDC},
	"oidc_sessions(tenant_id,user_id)":                      {"tenant_id,id", decisionOIDC},
	"identity_memberships(tenant_id,legacy_user_id)":        {"ownership_tenant_id,id", decisionIdentity},
	"identity_credentials(tenant_id,legacy_user_id)":        {"ownership_tenant_id,id", decisionIdentity},
	"identity_backfill_items(tenant_id,id)":                 {"ownership_tenant_id,id", decisionIdentity},
}

// Non-FK users consumers, reviewed by hand. They are listed so a reader sees the whole surface.
//
//	user_contact_challenges              composite FK through user_contacts(tenant_id,user_id,id); unchanged
//	user_notification_tombstones         (tenant_id,user_id) without FK; unchanged
//	users_consume_contact_challenges     AFTER UPDATE OF disabled trigger on users; fires for projected rows too
//	synapse_bridge_finding_assignee      reads users by ownership tenant and id; B members resolve by tenant-local id
//	synapse_track_assignee_review        reads users by name inside the tenant; unchanged
//	UserRepository.GetByAPIKeyHash       legacy bearer routing; unchanged until cutover (see raw-pool inventory)
//	UserRepository.Create/Update/Upsert  the only projection writers, inside the users tenant transaction
//	user_picker, personal_inbox, ownership_* and user_contact stores
//	                                     read users by ownership_tenant_id inside WithTenant; unchanged
//	audit_log actor strings              stay users.id ("operator" for bootstrap); never rewritten
var (
	usersReferencePattern = regexp.MustCompile(`(?is)(?:ALTER\s+TABLE\s+([a-z_]+)\s+ADD\s+CONSTRAINT\s+[a-z_]+\s+)?FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+users\s*\(([^)]*)\)`)
	createTablePattern    = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+([a-z_]+)\s*\(`)
)

func TestUsersConsumerInventory(t *testing.T) {
	found := map[string]string{}
	for file, up := range upMigrationSQL(t) {
		tables := createTablePattern.FindAllStringSubmatchIndex(up, -1)
		for _, m := range usersReferencePattern.FindAllStringSubmatchIndex(up, -1) {
			table := ""
			if m[2] >= 0 {
				table = up[m[2]:m[3]]
			} else {
				for _, tm := range tables {
					if tm[0] < m[0] {
						table = up[tm[2]:tm[3]]
					}
				}
			}
			cols := strings.ReplaceAll(up[m[4]:m[5]], " ", "")
			parent := strings.ReplaceAll(up[m[6]:m[7]], " ", "")
			key := strings.ToLower(table + "(" + cols + ")")
			if prior, dup := found[key]; dup && prior != parent {
				t.Errorf("%s: %s references users twice with different keys", file, key)
			}
			found[key] = parent
		}
	}
	var problems []string
	for key, parent := range found {
		want, ok := usersConsumers[key]
		switch {
		case !ok:
			problems = append(problems, "unreviewed users consumer "+key+" -> users("+parent+")")
		case want.parent != parent:
			problems = append(problems, "users consumer "+key+" now references users("+parent+"), inventory says users("+want.parent+")")
		}
	}
	for key := range usersConsumers {
		if _, ok := found[key]; !ok {
			problems = append(problems, "stale users consumer "+key)
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatal(strings.Join(problems, "\n"))
	}
}

func TestMigration0206IdentityFoundationRoundTrip(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 206, 205)
	for pass := 0; pass < 2; pass++ {
		if err := goose.UpTo(isolated.db, ".", 206); err != nil {
			t.Fatalf("pass %d: migrate up to 0206: %v", pass, err)
		}
		var tables int
		if err := isolated.db.QueryRow(`SELECT count(*) FROM pg_class WHERE relname LIKE 'identity_%' AND relkind='r' AND relforcerowsecurity`).Scan(&tables); err != nil {
			t.Fatal(err)
		}
		if tables != 18 {
			t.Fatalf("pass %d: %d identity tables with FORCE RLS, want 18", pass, tables)
		}
		if err := goose.DownTo(isolated.db, ".", 205); err != nil {
			t.Fatalf("pass %d: migrate down to 0205: %v", pass, err)
		}
		var left int
		if err := isolated.db.QueryRow(`SELECT (SELECT count(*) FROM pg_class WHERE relname LIKE 'identity_%')
			+ (SELECT count(*) FROM pg_proc WHERE proname LIKE 'synapse_identity_%' OR proname = 'synapse_enable_owner_only_rls')`).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Fatalf("pass %d: down left %d identity objects", pass, left)
		}
	}
}

func TestMigration0206DownRefusesEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed string
	}{
		{"person audit", `SELECT * FROM synapse_identity_person_command('person-down', 'person.created', 'platform-admin', 'down guard')`},
		{"shadow report", `DO $$ BEGIN
			INSERT INTO tenants(id, name) VALUES ('org-down', 'Org down');
			PERFORM set_config('app.current_tenant', 'org-down', true);
			INSERT INTO identity_shadow_reports(tenant_id, id, legacy_users, bootstrap_skipped, memberships, missing_memberships,
				credentials_expected, credentials_matched, authenticators_expected, authenticators_matched, authenticator_mismatches,
				digest_mismatches, routing_mismatches, role_drift, state_drift, placeholders, ambiguous, drift_total, max_drift, aborted, ready, rollback_prepared)
			VALUES ('org-down', 'report-down', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, true, true);
		END $$`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolated := newIsolatedMigrationDB(t, 206, 206)
			tx, err := isolated.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(tc.seed); err != nil {
				_ = tx.Rollback()
				t.Fatalf("seed evidence: %v", err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			err = goose.DownTo(isolated.db, ".", 205)
			if err == nil || !strings.Contains(err.Error(), "archive them and roll binaries back") {
				t.Fatalf("down with evidence = %v, want refusal", err)
			}
			// The refused Down rolled back completely: the tables remain, still under FORCE RLS.
			var forced int
			if err := isolated.db.QueryRow(`SELECT count(*) FROM pg_class
				WHERE relname IN ('identity_person_audit', 'identity_shadow_reports') AND relforcerowsecurity`).Scan(&forced); err != nil {
				t.Fatal(err)
			}
			if forced != 2 {
				t.Fatalf("refused down left %d evidence tables under FORCE RLS, want 2", forced)
			}
		})
	}
}
