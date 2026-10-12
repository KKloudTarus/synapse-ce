package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing/storetest"
)

func TestTicketStoreRejectsNilPool(t *testing.T) {
	if store, err := NewTicketStore(nil); store != nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil PostgreSQL pool: store=%v error=%v", store, err)
	}
}

func TestTicketStoreConformanceAndRLS(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate ticket schema: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	for _, tenant := range []string{"ticket-a", "ticket-b"} {
		suffix := "a"
		if tenant == "ticket-b" {
			suffix = "b"
		}
		eng := "ticket-engagement-" + suffix
		finding := "ticket-finding-" + suffix
		integration := "ticket-integration-" + suffix
		project := "ticket-project-" + suffix
		if _, e := pool.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT(id) DO NOTHING`, tenant); e != nil {
			t.Fatal(e)
		}
		err = WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,key,source_binding)
				VALUES ($1,$2,'Ticket project',$1,'{}'::jsonb) ON CONFLICT(id) DO NOTHING`, project, tenant)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO engagements (id,tenant_id,name,project_id)
				VALUES ($1,$2,'Ticket engagement',$3)
				ON CONFLICT(id) DO UPDATE SET project_id=EXCLUDED.project_id`, eng, tenant, project)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO findings (id,tenant_id,engagement_id,title)
				VALUES ($1,$2,$3,'Ticket finding') ON CONFLICT(id) DO NOTHING`, finding, tenant, eng)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO integrations
                (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
				VALUES ($1,$2,'jenkins','Ticket fixture','https://jenkins.example',now(),now())
                ON CONFLICT(id) DO NOTHING`, integration, tenant)
			return e
		})
		if err != nil {
			t.Fatalf("fixture %s: %v", tenant, err)
		}
	}
	t.Cleanup(func() {
		for _, tenant := range []string{"ticket-a", "ticket-b"} {
			_ = WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"ticket_intents", "ticket_links", "ticket_mappings"} {
					_, _ = tx.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
				}
				_, _ = tx.Exec(context.Background(), `DELETE FROM findings WHERE tenant_id=$1 AND id LIKE 'ticket-finding-%'`, tenant)
				_, _ = tx.Exec(context.Background(), `DELETE FROM integrations WHERE tenant_id=$1 AND id LIKE 'ticket-integration-%'`, tenant)
				_, _ = tx.Exec(context.Background(), `DELETE FROM engagements WHERE tenant_id=$1 AND id LIKE 'ticket-engagement-%'`, tenant)
				_, _ = tx.Exec(context.Background(), `DELETE FROM projects WHERE tenant_id=$1 AND id LIKE 'ticket-project-%'`, tenant)
				return nil
			})
		}
	})
	fixture := storetest.Fixture{Tenant: "ticket-a", Other: "ticket-b",
		Integration: "ticket-integration-a", Project: "ticket-project-a", Engagement: "ticket-engagement-a", Finding: "ticket-finding-a"}
	store, err := NewTicketStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	storetest.Run(t, store, fixture)
	storetest.ConcurrentReplay(t, store, fixture)
	storetest.ConcurrentClaim(t, store, fixture)
	storetest.ConcurrentCompletionConflict(t, store, fixture)
	storetest.CanceledContext(t, store, fixture)
	assertTicketStoreAuthoritativeProjectReferences(t, ctx, pool, store, fixture)
	for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents"} {
		var enabled, forced bool
		err = pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity
            FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced)
		if err != nil || !enabled || !forced {
			t.Fatalf("%s RLS enabled=%v forced=%v error=%v", table, enabled, forced, err)
		}
	}
	// The default test DSN usually bypasses RLS. Verify isolation under a real
	// NOSUPERUSER / NOBYPASSRLS role, not just through WHERE tenant_id.
	const role = "ticket_rls_probe"
	_, _ = pool.Exec(ctx, `DROP OWNED BY `+role)
	_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT,INSERT,UPDATE,DELETE ON ticket_mappings,ticket_links,ticket_intents TO ` + role,
	} {
		if _, err = pool.Exec(ctx, statement); err != nil {
			t.Fatalf("RLS role: %v", err)
		}
	}
	var superuser, bypassRLS bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=$1`, role).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		t.Fatalf("RLS probe role superuser=%t bypassrls=%t err=%v", superuser, bypassRLS, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	withRole := func(tenant string, fn func(pgx.Tx) error) error {
		return WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `SET LOCAL ROLE `+role); e != nil {
				return e
			}
			return fn(tx)
		})
	}
	for _, tenant := range []string{"ticket-b", ""} {
		for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents"} {
			err = withRole(tenant, func(tx pgx.Tx) error {
				var n int
				if e := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); e != nil {
					return e
				}
				if n != 0 {
					return fmt.Errorf("tenant %q saw %d rows of %s", tenant, n, table)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("RLS isolation for tenant %q on %s: %v", tenant, table, err)
			}
		}
	}
	for _, attempt := range []struct {
		table string
		query string
	}{
		{"ticket_mappings", `INSERT INTO ticket_mappings
            (id,tenant_id,integration_id,engagement_id,project_key,issue_type,version,created_at,updated_at)
            VALUES ('ticket-forged-mapping','ticket-a','ticket-integration-a','ticket-engagement-a','SEC','Bug',1,now(),now())`},
		{"ticket_links", `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,external_url,created_at)
            VALUES ('ticket-forged-link','ticket-a','ticket-finding-a',
                    'ticket-engagement-a','https://jira.example/browse/FORGED',now())`},
		{"ticket_intents", `INSERT INTO ticket_intents
            (id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,payload_digest,correlation_marker,created_at,updated_at)
            VALUES ('ticket-forged-intent','ticket-a','ticket-integration-a','ticket-map-a','ticket-finding-a','ticket-engagement-a','create','forged',repeat('a',64),'synapse-intent-ticket-forged-intent',now(),now())`},
	} {
		err = withRole("ticket-b", func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, attempt.query)
			return e
		})
		if err == nil {
			t.Fatalf("cross-tenant forged insert into %s passed RLS WITH CHECK", attempt.table)
		}
		err = withRole("", func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, attempt.query)
			return e
		})
		if err == nil {
			t.Fatalf("unbound forged insert into %s passed RLS WITH CHECK", attempt.table)
		}
	}
	for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents"} {
		var affected int64
		err = withRole("ticket-b", func(tx pgx.Tx) error {
			tag, e := tx.Exec(ctx, "UPDATE "+table+" SET tenant_id=tenant_id WHERE tenant_id='ticket-a'")
			affected = tag.RowsAffected()
			return e
		})
		if err != nil || affected != 0 {
			t.Fatalf("cross-tenant update on %s affected %d rows: %v", table, affected, err)
		}
	}
	// Bypass the domain deliberately: the database should still reject userinfo URLs.
	err = WithTenant(ctx, pool, "ticket-a", func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,external_url,created_at)
			VALUES ('ticket-bad-url','ticket-a','ticket-finding-a',
                    'ticket-engagement-a','https://user:token@jira.example/browse/SEC-1',now())`)
		return e
	})
	if err == nil {
		t.Fatal("database accepted credential-bearing link URL")
	}
	// FK constraints must reject a cross-tenant finding even under an elevated role.
	err = WithTenant(ctx, pool, "ticket-b", func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,external_url,created_at)
			VALUES ('ticket-cross-fk','ticket-b','ticket-finding-a',
                    'ticket-engagement-a','https://jira.example/browse/CROSS',now())`)
		return e
	})
	if err == nil {
		t.Fatal("cross-tenant finding passed composite FK")
	}
	_, err = store.GetMapping(ctx, "ticket-b", "ticket-map-a")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant mapping visible: %v", err)
	}
}

func assertTicketStoreAuthoritativeProjectReferences(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *TicketStore, f storetest.Fixture) {
	t.Helper()
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	projectMapping := ticketing.Mapping{ID: "ticket-project-map-a", TenantID: f.Tenant, IntegrationID: f.Integration,
		Scope: ticketing.Project, ScopeID: f.Project, ProjectKey: "SEC", IssueType: "Bug",
		Labels: []string{}, PriorityMap: map[string]string{}, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateMapping(ctx, f.Tenant, projectMapping); err != nil {
		t.Fatalf("create project-scoped mapping: %v", err)
	}
	intent := ticketing.Intent{ID: "ticket-project-intent-a", TenantID: f.Tenant, IntegrationID: f.Integration,
		MappingID: projectMapping.ID, FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create,
		RequestKey: "project-context", PayloadDigest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		Marker: "synapse-intent-ticket-project-intent-a", State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	if _, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); err != nil || !created {
		t.Fatalf("create intent against authoritative project context: created=%t err=%v", created, err)
	}

	const otherProject = "ticket-project-other-a"
	if err := WithTenant(ctx, pool, f.Tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,key,source_binding)
            VALUES($1,$2,'Other ticket project',$1,'{}'::jsonb)`, otherProject, f.Tenant.String())
		return err
	}); err != nil {
		t.Fatalf("seed unrelated project: %v", err)
	}
	t.Cleanup(func() {
		_ = WithTenant(context.Background(), pool, f.Tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `DELETE FROM projects WHERE tenant_id=$1 AND id=$2`, f.Tenant.String(), otherProject)
			return err
		})
	})
	wrongMapping := projectMapping
	wrongMapping.ID = "ticket-project-map-other-a"
	wrongMapping.ScopeID = otherProject
	wrongMapping.CreatedAt = now.Add(time.Second)
	wrongMapping.UpdatedAt = wrongMapping.CreatedAt
	if err := store.CreateMapping(ctx, f.Tenant, wrongMapping); err != nil {
		t.Fatalf("create unrelated project mapping: %v", err)
	}
	wrongIntent := intent
	wrongIntent.ID = "ticket-project-intent-other-a"
	wrongIntent.MappingID = wrongMapping.ID
	wrongIntent.RequestKey = "wrong-project-context"
	wrongIntent.Marker = "synapse-intent-" + wrongIntent.ID.String()
	if _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, wrongIntent); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("project mapping accepted another project's engagement: %v", err)
	}
	missingFinding := intent
	missingFinding.ID = "ticket-project-intent-missing-a"
	missingFinding.FindingID = "ticket-finding-missing-a"
	missingFinding.RequestKey = "missing-finding"
	missingFinding.Marker = "synapse-intent-" + missingFinding.ID.String()
	if _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, missingFinding); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing finding accepted for ticket intent: %v", err)
	}
}

func TestTicketStorePersistsAfterPoolReopen(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate ticket schema: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	const tenant = "ticket-reopen"
	const engagement = "ticket-reopen-engagement"
	const finding = "ticket-reopen-finding"
	const integration = "ticket-reopen-integration"
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT(id) DO NOTHING`, tenant); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Ticket reopen engagement') ON CONFLICT(id) DO NOTHING`, []any{engagement, tenant}},
			{`INSERT INTO findings (id,tenant_id,engagement_id,title) VALUES ($1,$2,$3,'Ticket reopen finding') ON CONFLICT(id) DO NOTHING`, []any{finding, tenant, engagement}},
			{`INSERT INTO integrations (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
                VALUES ($1,$2,'jenkins','Ticket reopen fixture','https://jenkins.example',now(),now()) ON CONFLICT(id) DO NOTHING`, []any{integration, tenant}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		pool.Close()
		t.Fatalf("seed reopen fixture: %v", err)
	}

	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	store, err := NewTicketStore(pool)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	mapping := ticketing.Mapping{ID: "ticket-reopen-mapping", TenantID: tenant, IntegrationID: integration,
		Scope: ticketing.Engagement, ScopeID: engagement, ProjectKey: "SEC", IssueType: "Bug",
		Labels: []string{}, PriorityMap: map[string]string{}, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateMapping(ctx, tenant, mapping); err != nil {
		pool.Close()
		t.Fatalf("create mapping before reopen: %v", err)
	}
	intent := ticketing.Intent{ID: "ticket-reopen-intent", TenantID: tenant, IntegrationID: integration,
		MappingID: mapping.ID, FindingID: finding, EngagementID: engagement, Action: ticketing.Create,
		RequestKey: "reopen", PayloadDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Marker: "synapse-intent-ticket-reopen-intent", State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	if _, created, err := store.CreateOrGetIntent(ctx, tenant, intent); err != nil || !created {
		pool.Close()
		t.Fatalf("create intent before reopen: created=%v err=%v", created, err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(ctx, tenant, intent.ID, 1, ticketing.IntentTransition{
		Event: writeintent.Claim, LeaseUntil: &lease,
	}, now)
	if err != nil || claimed.State != writeintent.InFlight || claimed.Version != 2 || claimed.Attempts != 1 {
		pool.Close()
		t.Fatalf("claim intent before reopen: %+v, %v", claimed, err)
	}
	pool.Close()

	pool, err = Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
			for _, table := range []string{"ticket_intents", "ticket_links", "ticket_mappings"} {
				_, _ = tx.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
			}
			_, _ = tx.Exec(context.Background(), `DELETE FROM findings WHERE tenant_id=$1 AND id=$2`, tenant, finding)
			_, _ = tx.Exec(context.Background(), `DELETE FROM integrations WHERE tenant_id=$1 AND id=$2`, tenant, integration)
			_, _ = tx.Exec(context.Background(), `DELETE FROM engagements WHERE tenant_id=$1 AND id=$2`, tenant, engagement)
			return nil
		})
		pool.Close()
	})

	store, err = NewTicketStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	gotMapping, err := store.GetMapping(ctx, tenant, mapping.ID)
	if err != nil || gotMapping.ID != mapping.ID || gotMapping.ProjectKey != mapping.ProjectKey {
		t.Fatalf("mapping after pool reopen: %+v, %v", gotMapping, err)
	}
	gotIntent, err := store.GetIntent(ctx, tenant, intent.ID)
	if err != nil || gotIntent.ID != intent.ID || gotIntent.State != writeintent.InFlight || gotIntent.Version != 2 || gotIntent.Attempts != 1 || gotIntent.LeaseUntil == nil || !gotIntent.LeaseUntil.Equal(lease) {
		t.Fatalf("intent after pool reopen: %+v, %v", gotIntent, err)
	}
	if _, err := store.TransitionIntent(ctx, tenant, intent.ID, 2, ticketing.IntentTransition{
		Event: writeintent.Acknowledge, Remote: &ticketing.RemoteTicket{ID: "SEC-INVALID", URL: "https://user:token@jira.example/browse/SEC-INVALID"},
	}, lease); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid completion remote accepted: %v", err)
	}
	unchanged, err := store.GetIntent(ctx, tenant, intent.ID)
	if err != nil || unchanged.State != writeintent.InFlight || unchanged.Version != 2 || unchanged.RemoteID != "" || unchanged.RemoteURL != "" || unchanged.ErrorCode != "" {
		t.Fatalf("invalid completion partially changed intent: %+v, %v", unchanged, err)
	}
	if links, listErr := store.ListLinks(ctx, tenant, finding); listErr != nil || len(links) != 0 {
		t.Fatalf("invalid completion created a link: %+v, %v", links, listErr)
	}
	uncertain, err := store.TransitionIntent(ctx, tenant, intent.ID, 2, ticketing.IntentTransition{
		Event: writeintent.LeaseExpired,
	}, lease)
	if err != nil || uncertain.State != writeintent.Uncertain {
		t.Fatalf("expired lease after pool reopen: %+v, %v", uncertain, err)
	}
	if _, err := store.TransitionIntent(ctx, tenant, intent.ID, 3, ticketing.IntentTransition{
		Event: writeintent.Claim, LeaseUntil: &lease,
	}, lease.Add(time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("blind claim after reopened uncertain intent: %v", err)
	}
	remote := ticketing.RemoteTicket{ID: "SEC-REOPEN-1", URL: "https://jira.example/browse/SEC-REOPEN-1"}
	done, err := store.TransitionIntent(ctx, tenant, intent.ID, 3, ticketing.IntentTransition{
		Event: writeintent.ReconcileFound, Remote: &remote,
	}, lease.Add(2*time.Second))
	if err != nil || done.State != writeintent.Done || done.Version != 4 || done.RemoteID != remote.ID ||
		done.RemoteURL != remote.URL || done.ErrorCode != "" {
		t.Fatalf("reconcile completed intent before second reopen: %+v, %v", done, err)
	}

	pool.Close()
	pool, err = Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	store, err = NewTicketStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	durable, err := store.GetIntent(ctx, tenant, intent.ID)
	if err != nil || durable.State != writeintent.Done || durable.Version != 4 || durable.RemoteID != remote.ID ||
		durable.RemoteURL != remote.URL || durable.ErrorCode != "" {
		t.Fatalf("completed intent after second pool reopen: %+v, %v", durable, err)
	}
	links, err := store.ListLinks(ctx, tenant, finding)
	if err != nil || len(links) != 1 || links[0].ID != intent.ID || links[0].IntegrationID != integration ||
		links[0].ExternalID != remote.ID || links[0].ExternalURL != remote.URL {
		t.Fatalf("completion link after second pool reopen: %+v, %v", links, err)
	}
}
