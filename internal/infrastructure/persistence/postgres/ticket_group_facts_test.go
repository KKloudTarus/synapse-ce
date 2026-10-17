package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTicketGroupFactsPostgresAttribution(t *testing.T) {
	ctx := context.Background()
	dsn := testDSN(t)
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var unique [8]byte
	if _, err := rand.Read(unique[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "group-facts-" + hex.EncodeToString(unique[:]) + "-"
	id := func(suffix string) shared.ID { return shared.ID(prefix + suffix) }
	tenant := id("tenant")
	if _, err = pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES($1,'Group facts test') ON CONFLICT(id)DO NOTHING`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = WithTenant(context.Background(), pool, tenant.String(), func(tx pgx.Tx) error {
			for _, table := range []string{"notification_engagement_settings", "ticket_status_sync", "ticket_group_members", "ticket_groups", "ticket_mappings", "attack_path_edges", "fleet_assets", "findings", "engagements", "projects", "integrations"} {
				if _, e := tx.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant.String()); e != nil {
					t.Error(e)
				}
			}
			return nil
		})
	})
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		queries := []string{
			`INSERT INTO projects(id,tenant_id,name,key,source_binding)VALUES('group-facts-project',$1,'Group facts','group-facts','{}'::jsonb)`,
			`INSERT INTO engagements(id,tenant_id,name,project_id)VALUES('group-facts-eng',$1,'Group facts','group-facts-project')`,
			`INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,created_at,updated_at)VALUES('group-facts-integration',$1,'jira-cloud','Group facts','https://unit.atlassian.net',now(),now())`,
			`INSERT INTO findings(id,tenant_id,engagement_id,title,kind,advisory_id)VALUES('group-facts-one',$1,'group-facts-eng','No inferred attribution','manual','CVE-2026-12345'),('group-facts-two',$1,'group-facts-eng','prose.example is not an asset','manual','CVE-2026-12345')`,
			`INSERT INTO fleet_assets(id,tenant_id,kind,key,name,attributes)VALUES('group-facts-asset',$1,'host','stored.example','Stored asset','{}'::jsonb)`,
			`INSERT INTO attack_path_edges(tenant_id,engagement_id,from_kind,from_id,to_kind,to_id,target_kind,canonical_finding_id,kind,producer,provenance,confidence)VALUES($1,'group-facts-eng','asset','group-facts-asset','finding','group-facts-one','canonical','group-facts-one','affected_by','group-facts-producer','group-facts-provenance','observed')`,
		}
		for _, query := range queries {
			if _, err := tx.Exec(ctx, strings.ReplaceAll(query, "group-facts-", prefix), tenant.String()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTicketStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	mapping := ticketing.Mapping{ID: id("map"), TenantID: tenant, IntegrationID: id("integration"), Scope: ticketing.Project, ScopeID: id("project"), ProjectKey: "SEC", IssueType: "10001", DataClass: notification.DataClassDetail, GroupingMode: ticketing.GroupingVulnerabilityProject, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err = store.CreateMapping(ctx, tenant, mapping); err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, strings.ReplaceAll(`INSERT INTO ticket_groups(tenant_id,id,mapping_id,project_id,vulnerability_id,integration_id,endpoint,project_key,issue_type,security_level,created_at,updated_at)VALUES($1,'group-facts-group','group-facts-map','group-facts-project','CVE-2026-12345','group-facts-integration','https://unit.atlassian.net','SEC','10001','restricted',now(),now())`, "group-facts-", prefix), tenant.String())
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, strings.ReplaceAll(`INSERT INTO ticket_group_members(tenant_id,group_id,engagement_id,finding_id,created_at)VALUES($1,'group-facts-group','group-facts-eng','group-facts-one',now())`, "group-facts-", prefix), tenant.String())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, found, err := store.GetTicketGroup(ctx, tenant, mapping.ID, mapping.ScopeID, "CVE-2026-12345")
	if err != nil || !found {
		t.Fatalf("load unsubmitted group: found=%t group=%+v err=%v", found, stored, err)
	}
	if !stored.IntentID.IsZero() || stored.Remote.ID != "" || stored.Remote.URL != "" {
		t.Fatalf("unsubmitted group should not have intent or remote ticket: %+v", stored)
	}
	candidate := ports.TicketGroupMember{EngagementID: id("eng"), FindingID: id("two")}
	facts, err := store.GroupTicketFacts(ctx, tenant, mapping.ID, mapping.ScopeID, "CVE-2026-12345", candidate)
	if err != nil || len(facts) != 2 {
		t.Fatalf("facts=%+v err=%v", facts, err)
	}
	if facts[0].AssetID != id("asset") || facts[0].AssetName != "Stored asset" || facts[1].AssetID != "" || facts[1].AssetName != "" {
		t.Fatalf("incorrect attribution: %+v", facts)
	}
	if _, err = store.GroupTicketFacts(ctx, "foreign-tenant", mapping.ID, mapping.ScopeID, "CVE-2026-12345", candidate); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant facts: %v", err)
	}
	if _, err = store.GroupTicketFacts(ctx, tenant, mapping.ID, "foreign-project", "CVE-2026-12345", candidate); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-project facts: %v", err)
	}
	if err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_engagement_settings(tenant_id,engagement_id,external_notifications,revision,updated_at,updated_by) VALUES($1,$2,'none',1,now(),'test-reviewer')`, tenant.String(), id("eng").String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	facts, err = store.GroupTicketFacts(ctx, tenant, mapping.ID, mapping.ScopeID, "CVE-2026-12345", candidate)
	if err != nil || len(facts) != 2 || facts[0].ExternalNotifications != notification.EngagementNotificationsNone || facts[1].ExternalNotifications != notification.EngagementNotificationsNone {
		t.Fatalf("member privacy facts=%+v err=%v", facts, err)
	}
	assertTicketGroupAndStatusRLS(t, pool, tenant, prefix)
}

func assertTicketGroupAndStatusRLS(t *testing.T, pool *pgxpool.Pool, tenant shared.ID, prefix string) {
	t.Helper()
	ctx := context.Background()
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ticket_status_sync(tenant_id,mapping_id,finding_id,engagement_id,desired_state,source_revision,created_at,updated_at,checked_at) VALUES($1,$2,$3,$4,'reopen','stored-status',now(),now(),now())`, tenant.String(), prefix+"map", prefix+"one", prefix+"eng")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	role := pgx.Identifier{strings.ReplaceAll(prefix, "-", "_") + "probe"}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOSUPERUSER NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DROP OWNED BY "+role)
		_, _ = pool.Exec(ctx, "DROP ROLE "+role)
	})
	for _, query := range []string{"GRANT USAGE ON SCHEMA public TO " + role, "GRANT SELECT,INSERT,UPDATE,DELETE ON ticket_groups,ticket_group_members,ticket_status_sync TO " + role} {
		if _, err := pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"ticket_groups", "ticket_group_members", "ticket_status_sync"} {
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced); err != nil || !enabled || !forced {
			t.Fatalf("%s RLS enabled=%v forced=%v err=%v", table, enabled, forced, err)
		}
		for _, boundTenant := range []string{tenant.String(), "foreign-tenant", ""} {
			err := WithTenant(ctx, pool, boundTenant, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
					return err
				}
				var count int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant.String()).Scan(&count); err != nil {
					return err
				}
				want := 0
				if boundTenant == tenant.String() {
					want = 1
				}
				if count != want {
					t.Fatalf("%s bound=%q rows=%d want=%d", table, boundTenant, count, want)
				}
				if boundTenant != tenant.String() {
					for _, query := range []string{"UPDATE " + table + " SET tenant_id=tenant_id WHERE tenant_id=$1", "DELETE FROM " + table + " WHERE tenant_id=$1"} {
						tag, err := tx.Exec(ctx, query, tenant.String())
						if err != nil || tag.RowsAffected() != 0 {
							t.Fatalf("cross-tenant mutation %s: affected=%d err=%v", table, tag.RowsAffected(), err)
						}
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, query := range []string{
		`INSERT INTO ticket_groups(tenant_id,id,mapping_id,project_id,vulnerability_id,integration_id,endpoint,project_key,issue_type,security_level,created_at,updated_at) VALUES($1,$2||'forged-group',$2||'map',$2||'project','CVE-forged',$2||'integration','https://unit.atlassian.net','SEC','10001','restricted',now(),now())`,
		`INSERT INTO ticket_group_members(tenant_id,group_id,engagement_id,finding_id,created_at) VALUES($1,$2||'group',$2||'eng',$2||'two',now())`,
		`INSERT INTO ticket_status_sync(tenant_id,mapping_id,finding_id,engagement_id,desired_state,source_revision,created_at,updated_at,checked_at) VALUES($1,$2||'map',$2||'two',$2||'eng','reopen','forged',now(),now(),now())`,
	} {
		for _, boundTenant := range []string{"foreign-tenant", ""} {
			err := WithTenant(ctx, pool, boundTenant, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, query, tenant.String(), prefix)
				return err
			})
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != "42501" {
				t.Fatalf("forged row needs RLS refusal, got %v", err)
			}
		}
	}
}
