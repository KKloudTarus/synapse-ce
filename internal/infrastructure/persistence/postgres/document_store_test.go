package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/docpublishconformance"
)

// requireDocumentConstraint fails unless err is the database refusing the row for the intended
// reason. A statement that is merely malformed also errors, and must not pass for a guard.
func requireDocumentConstraint(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("expected SQLSTATE %s, got %v", code, err)
	}
}

// wantDocumentConstraintCode is 23503 (foreign key) for a reference into another tenant and
// 23514 (check) for every other row the domain would refuse.
func wantDocumentConstraintCode(name string) string {
	if strings.Contains(name, "another tenant") {
		return "23503"
	}
	return "23514"
}

func TestDocumentStoreRejectsNilPool(t *testing.T) {
	if store, err := NewDocumentStore(nil); store != nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil PostgreSQL pool: store=%v error=%v", store, err)
	}
}

var documentTables = []string{"document_links", "document_intents"}

func documentFixture() docpublishconformance.Fixture {
	return docpublishconformance.Fixture{
		Tenant: "doc-a", Other: "doc-b", Integration: "doc-integration-a",
		Engagement: "doc-engagement-a", Project: "doc-project-a",
		OtherEngagement: "doc-engagement-b", OtherProject: "doc-project-b",
	}
}

// seedDocumentTenants makes the rows the conformance fixture names, for both tenants, and
// removes everything it and the suite created when the test ends.
func seedDocumentTenants(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, row := range []struct{ tenant, engagement, project, integration string }{
		{"doc-a", "doc-engagement-a", "doc-project-a", "doc-integration-a"},
		{"doc-b", "doc-engagement-b", "doc-project-b", "doc-integration-b"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT(id) DO NOTHING`, row.tenant); err != nil {
			t.Fatal(err)
		}
		err := WithTenant(ctx, pool, row.tenant, func(tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,key,source_binding)
				VALUES ($1,$2,'Document project',$1,'{}'::jsonb) ON CONFLICT(id) DO NOTHING`, row.project, row.tenant); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `INSERT INTO engagements (id,tenant_id,name)
				VALUES ($1,$2,'Document engagement') ON CONFLICT(id) DO NOTHING`, row.engagement, row.tenant); e != nil {
				return e
			}
			_, e := tx.Exec(ctx, `INSERT INTO integrations (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
				VALUES ($1,$2,'jenkins','Document fixture','https://jenkins.example',now(),now())
				ON CONFLICT(id) DO NOTHING`, row.integration, row.tenant)
			return e
		})
		if err != nil {
			t.Fatalf("document fixture %s: %v", row.tenant, err)
		}
	}
	t.Cleanup(func() {
		for _, tenant := range []string{"doc-a", "doc-b"} {
			_ = WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
				for _, table := range documentTables {
					_, _ = tx.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
				}
				_, _ = tx.Exec(context.Background(), `DELETE FROM integrations WHERE tenant_id=$1 AND id LIKE 'doc-integration-%'`, tenant)
				_, _ = tx.Exec(context.Background(), `DELETE FROM engagements WHERE tenant_id=$1 AND id LIKE 'doc-engagement-%'`, tenant)
				_, _ = tx.Exec(context.Background(), `DELETE FROM projects WHERE tenant_id=$1 AND id LIKE 'doc-project-%'`, tenant)
				return nil
			})
		}
	})
}

func TestDocumentStoreConformanceAndRLS(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate document schema: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	seedDocumentTenants(t, ctx, pool)
	f := documentFixture()
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	docpublishconformance.Run(t, store, f)
	docpublishconformance.ConcurrentReplay(t, store, f)
	docpublishconformance.ConcurrentClaim(t, store, f)
	docpublishconformance.ConcurrentCompletionConflict(t, store, f)
	docpublishconformance.ConcurrentUpdateCompletion(t, store, f)
	docpublishconformance.CanceledContext(t, store, f)

	t.Run("an unknown or foreign integration is not found", func(t *testing.T) {
		target := docpublish.Target{IntegrationID: "doc-integration-missing", SourceKind: docpublish.EngagementReport,
			SourceRef: "engagement-report", Scope: docpublish.Engagement, ScopeID: f.Engagement, Container: "INT"}
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		intent := docpublish.Intent{ID: "doc-no-integration", TenantID: f.Tenant, Target: target, Action: docpublish.Create,
			RequestKey: "no-integration", PayloadDigest: strings.Repeat("a", 64), ContentHash: strings.Repeat("b", 64),
			Marker: docpublish.MarkerFor("doc-no-integration"), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
		if _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("unknown integration accepted: %v", err)
		}
		intent.ID, intent.Marker, intent.RequestKey = "doc-foreign-integration", docpublish.MarkerFor("doc-foreign-integration"), "foreign-integration"
		intent.IntegrationID = "doc-integration-b"
		if _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("another tenant's integration accepted: %v", err)
		}
	})

	for _, table := range documentTables {
		var enabled, forced bool
		if err = pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).
			Scan(&enabled, &forced); err != nil || !enabled || !forced {
			t.Fatalf("%s RLS enabled=%v forced=%v error=%v", table, enabled, forced, err)
		}
	}

	// The default test DSN usually bypasses RLS. Verify isolation under a real
	// NOSUPERUSER / NOBYPASSRLS role, not just through WHERE tenant_id.
	const role = "doc_rls_probe"
	_, _ = pool.Exec(ctx, `DROP OWNED BY `+role)
	_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT,INSERT,UPDATE,DELETE ON document_links,document_intents TO ` + role,
	} {
		if _, err = pool.Exec(ctx, statement); err != nil {
			t.Fatalf("RLS role: %v", err)
		}
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
	// doc-a has rows (the suite just wrote them); another tenant and an unbound session see none.
	for _, table := range documentTables {
		var own int
		if err = withRole("doc-a", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&own)
		}); err != nil || own == 0 {
			t.Fatalf("tenant doc-a sees %d rows of %s: %v", own, table, err)
		}
		for _, tenant := range []string{"doc-b", ""} {
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
				t.Fatalf("RLS isolation on %s: %v", table, err)
			}
		}
		var affected int64
		err = withRole("doc-b", func(tx pgx.Tx) error {
			tag, e := tx.Exec(ctx, "UPDATE "+table+" SET tenant_id=tenant_id WHERE tenant_id='doc-a'")
			affected = tag.RowsAffected()
			return e
		})
		if err != nil || affected != 0 {
			t.Fatalf("cross-tenant update on %s affected %d rows: %v", table, affected, err)
		}
	}
	for _, attempt := range []struct{ table, query string }{
		{"document_links", `INSERT INTO document_links
            (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,remote_page_id,remote_version,remote_url,content_hash,revision,created_at,updated_at)
            VALUES ('doc-forged-link','doc-a','doc-integration-a','engagement_report','forged','doc-engagement-a','FORGED','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`},
		{"document_intents", `INSERT INTO document_intents
            (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,action,request_key,payload_digest,content_hash,correlation_marker,created_at,updated_at)
            VALUES ('doc-forged-intent','doc-a','doc-integration-a','engagement_report','forged','doc-engagement-a','FORGED','create','forged',repeat('a',64),repeat('b',64),'synapse-intent-doc-forged-intent',now(),now())`},
	} {
		for _, tenant := range []string{"doc-b", ""} {
			err = withRole(tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, attempt.query)
				return e
			})
			if err == nil {
				t.Fatalf("forged insert into %s as tenant %q passed RLS WITH CHECK", attempt.table, tenant)
			}
		}
	}

	t.Run("the schema rejects what the domain would", func(t *testing.T) {
		linkBase := func(mutations string) string {
			return `INSERT INTO document_links
                (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,project_id,container,remote_page_id,remote_version,remote_url,content_hash,revision,created_at,updated_at)
                VALUES ` + mutations
		}
		for name, statement := range map[string]string{
			"credential URL":                     linkBase(`('doc-bad-url','doc-a','doc-integration-a','engagement_report','u','doc-engagement-a',NULL,'U','1',1,'https://user:token@wiki.example/p',repeat('a',64),1,now(),now())`),
			"query URL":                          linkBase(`('doc-bad-query','doc-a','doc-integration-a','engagement_report','q','doc-engagement-a',NULL,'Q','1',1,'https://wiki.example/p?t=1',repeat('a',64),1,now(),now())`),
			"plain http URL":                     linkBase(`('doc-bad-http','doc-a','doc-integration-a','engagement_report','h','doc-engagement-a',NULL,'H','1',1,'http://wiki.example/p',repeat('a',64),1,now(),now())`),
			"unknown kind":                       linkBase(`('doc-bad-kind','doc-a','doc-integration-a','wiki_page','k','doc-engagement-a',NULL,'K','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`),
			"kind in the wrong scope":            linkBase(`('doc-bad-scope','doc-a','doc-integration-a','engagement_report','s',NULL,'doc-project-a','S','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`),
			"closure report in engagement scope": linkBase(`('doc-bad-closure','doc-a','doc-integration-a','assessment_closure_report','c','doc-engagement-a',NULL,'C','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`),
			"both scopes":                        linkBase(`('doc-bad-both','doc-a','doc-integration-a','engagement_report','b','doc-engagement-a','doc-project-a','B','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`),
			"no scope":                           linkBase(`('doc-bad-none','doc-a','doc-integration-a','engagement_report','n',NULL,NULL,'N','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`),
			"uppercase hash":                     linkBase(`('doc-bad-hash','doc-a','doc-integration-a','engagement_report','x','doc-engagement-a',NULL,'X','1',1,'https://wiki.example/p',repeat('A',64),1,now(),now())`),
			"zero version":                       linkBase(`('doc-bad-version','doc-a','doc-integration-a','engagement_report','v','doc-engagement-a',NULL,'V','1',0,'https://wiki.example/p',repeat('a',64),1,now(),now())`),
			"blank container":                    linkBase(`('doc-bad-container','doc-a','doc-integration-a','engagement_report','c2','doc-engagement-a',NULL,' ','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`),
			"zero revision":                      linkBase(`('doc-bad-revision','doc-a','doc-integration-a','engagement_report','r','doc-engagement-a',NULL,'R','1',1,'https://wiki.example/p',repeat('a',64),0,now(),now())`),
			"updated before created":             linkBase(`('doc-bad-time','doc-a','doc-integration-a','engagement_report','t','doc-engagement-a',NULL,'T','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now()-interval '1 hour')`),
			"engagement of another tenant":       linkBase(`('doc-cross-fk','doc-a','doc-integration-a','engagement_report','f','doc-engagement-b',NULL,'F','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`),
			"integration of another tenant":      linkBase(`('doc-cross-int','doc-a','doc-integration-b','engagement_report','i','doc-engagement-a',NULL,'I','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`),
		} {
			t.Run(name, func(t *testing.T) {
				err := WithTenant(ctx, pool, "doc-a", func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, statement)
					return e
				})
				requireDocumentConstraint(t, err, wantDocumentConstraintCode(name))
			})
		}
		intentBase := func(values string) string {
			return `INSERT INTO document_intents
                (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,link_id,action,request_key,payload_digest,content_hash,correlation_marker,state,remote_id,remote_url,remote_version,created_at,updated_at)
                VALUES ` + values
		}
		for name, statement := range map[string]string{
			"create with a link":     intentBase(`('doc-bad-i1','doc-a','doc-integration-a','engagement_report','i','doc-engagement-a','I','l','create','bad-1',repeat('a',64),repeat('b',64),'synapse-intent-doc-bad-i1','pending','','',0,now(),now())`),
			"update without a link":  intentBase(`('doc-bad-i2','doc-a','doc-integration-a','engagement_report','i','doc-engagement-a','I',NULL,'update','bad-2',repeat('a',64),repeat('b',64),'synapse-intent-doc-bad-i2','pending','','',0,now(),now())`),
			"delete action":          intentBase(`('doc-bad-i3','doc-a','doc-integration-a','engagement_report','i','doc-engagement-a','I',NULL,'delete','bad-3',repeat('a',64),repeat('b',64),'synapse-intent-doc-bad-i3','pending','','',0,now(),now())`),
			"done without a version": intentBase(`('doc-bad-i4','doc-a','doc-integration-a','engagement_report','i','doc-engagement-a','I',NULL,'create','bad-4',repeat('a',64),repeat('b',64),'synapse-intent-doc-bad-i4','done','p','https://wiki.example/p',0,now(),now())`),
			"pending with a version": intentBase(`('doc-bad-i5','doc-a','doc-integration-a','engagement_report','i','doc-engagement-a','I',NULL,'create','bad-5',repeat('a',64),repeat('b',64),'synapse-intent-doc-bad-i5','pending','','',2,now(),now())`),
			"foreign marker":         intentBase(`('doc-bad-i6','doc-a','doc-integration-a','engagement_report','i','doc-engagement-a','I',NULL,'create','bad-6',repeat('a',64),repeat('b',64),'synapse-intent-other-id-12','pending','','',0,now(),now())`),
			"bad content hash":       intentBase(`('doc-bad-i7','doc-a','doc-integration-a','engagement_report','i','doc-engagement-a','I',NULL,'create','bad-7',repeat('a',64),'xyz','synapse-intent-doc-bad-i7','pending','','',0,now(),now())`),
		} {
			t.Run("intent "+name, func(t *testing.T) {
				err := WithTenant(ctx, pool, "doc-a", func(tx pgx.Tx) error {
					_, e := tx.Exec(ctx, statement)
					return e
				})
				requireDocumentConstraint(t, err, wantDocumentConstraintCode(name))
			})
		}
	})

	t.Run("a linked scope parent cannot be deleted from under its documents", func(t *testing.T) {
		err := WithTenant(ctx, pool, "doc-a", func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `DELETE FROM engagements WHERE tenant_id='doc-a' AND id='doc-engagement-a'`)
			return e
		})
		requireDocumentConstraint(t, err, "23503")
		err = WithTenant(ctx, pool, "doc-a", func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `DELETE FROM projects WHERE tenant_id='doc-a' AND id='doc-project-a'`)
			return e
		})
		requireDocumentConstraint(t, err, "23503")
	})

	t.Run("one link per target is a database guarantee", func(t *testing.T) {
		err := WithTenant(ctx, pool, "doc-a", func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO document_links
                (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,remote_page_id,remote_version,remote_url,content_hash,revision,created_at,updated_at)
                SELECT 'doc-twin',tenant_id,integration_id,source_kind,source_ref,engagement_id,container,'99',1,'https://wiki.example/p',content_hash,1,now(),now()
                FROM document_links WHERE tenant_id='doc-a' AND container='SEC' AND source_kind='engagement_report'`)
			return e
		})
		requireDocumentConstraint(t, err, "23505")
	})
}

func TestDocumentStorePersistsAfterPoolReopen(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate document schema: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { pool.Close() }()
	const tenant, engagement, integration = "doc-reopen", "doc-reopen-engagement", "doc-reopen-integration"
	if _, err = pool.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT(id) DO NOTHING`, tenant); err != nil {
		t.Fatal(err)
	}
	if err = WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Reopen') ON CONFLICT(id) DO NOTHING`, engagement, tenant); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO integrations (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
            VALUES ($1,$2,'jenkins','Reopen','https://jenkins.example',now(),now()) ON CONFLICT(id) DO NOTHING`, integration, tenant)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p, e := Connect(context.Background(), dsn)
		if e != nil {
			return
		}
		defer p.Close()
		_ = WithTenant(context.Background(), p, tenant, func(tx pgx.Tx) error {
			for _, table := range documentTables {
				_, _ = tx.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
			}
			_, _ = tx.Exec(context.Background(), `DELETE FROM integrations WHERE tenant_id=$1 AND id=$2`, tenant, integration)
			_, _ = tx.Exec(context.Background(), `DELETE FROM engagements WHERE tenant_id=$1 AND id=$2`, tenant, engagement)
			return nil
		})
	})

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	target := docpublish.Target{IntegrationID: integration, SourceKind: docpublish.EngagementReport,
		SourceRef: "engagement-report", Scope: docpublish.Engagement, ScopeID: engagement, Container: "SEC"}
	intent := docpublish.Intent{ID: "doc-reopen-intent", TenantID: tenant, Target: target, Action: docpublish.Create,
		RequestKey: "reopen", PayloadDigest: strings.Repeat("a", 64), ContentHash: strings.Repeat("b", 64),
		Marker: docpublish.MarkerFor("doc-reopen-intent"), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.CreateOrGetIntent(ctx, tenant, intent); err != nil || !created {
		t.Fatalf("create intent: created=%t err=%v", created, err)
	}
	lease := now.Add(time.Hour)
	if _, err = store.TransitionIntent(ctx, tenant, intent.ID, 1,
		docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(time.Second)); err != nil {
		t.Fatalf("claim: %v", err)
	}
	pool.Close()

	pool, err = Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetIntent(ctx, tenant, intent.ID)
	if err != nil || got.State != writeintent.InFlight || got.Attempts != 1 || got.Version != 2 ||
		got.LeaseUntil == nil || !got.LeaseUntil.Equal(lease) {
		t.Fatalf("intent after reopen: %+v %v", got, err)
	}
	done, err := reopened.TransitionIntent(ctx, tenant, intent.ID, 2, docpublish.IntentTransition{Event: writeintent.Acknowledge,
		Remote: &docpublish.RemotePage{ID: "7", Version: 1, URL: "https://wiki.example/pages/7"}}, now.Add(2*time.Second))
	if err != nil || done.State != writeintent.Done {
		t.Fatalf("complete after reopen: %+v %v", done, err)
	}
	link, err := reopened.FindLink(ctx, tenant, target)
	if err != nil || link.RemotePageID != "7" || link.ID != intent.ID {
		t.Fatalf("link after reopen: %+v %v", link, err)
	}
}
