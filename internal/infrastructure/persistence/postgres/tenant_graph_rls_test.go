package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAssessmentGraphRLSKnownIDIsolation(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	prefix := "graph-" + uuid.NewString()
	tenantA, tenantB := prefix+"-a", prefix+"-b"
	engagementA, engagementB := prefix+"-eng-a", prefix+"-eng-b"
	findingA := prefix + "-finding-a"
	ids := map[string]string{
		"engagements":      engagementA,
		"scope_targets":    prefix + "-scope-a",
		"findings":         findingA,
		"evidence":         prefix + "-evidence-a",
		"finding_comments": prefix + "-comment-a",
		"finding_retests":  prefix + "-retest-a",
		"imported_sboms":   prefix + "-sbom-a",
		"writeup_drafts":   prefix + "-draft-a",
		"jobs":             prefix + "-job-a",
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,'A'),($2,'B')`, []any{tenantA, tenantB}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'A'),($3,$4,'B')`, []any{engagementA, tenantA, engagementB, tenantB}},
		{`INSERT INTO scope_targets(id,tenant_id,engagement_id,in_scope,kind,value) VALUES($1,$2,$3,true,'url','https://a.example')`, []any{ids["scope_targets"], tenantA, engagementA}},
		{`INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($1,$2,$3,'A finding')`, []any{findingA, tenantA, engagementA}},
		{`INSERT INTO evidence(id,tenant_id,finding_id,engagement_id,kind,sha256,storage_ref,content) VALUES($1,$2,$3,$4,'artifact',$1,$1,'a')`, []any{ids["evidence"], tenantA, findingA, engagementA}},
		{`INSERT INTO finding_comments(id,tenant_id,engagement_id,finding_id,author,body) VALUES($1,$2,$3,$4,'alice','a')`, []any{ids["finding_comments"], tenantA, engagementA, findingA}},
		{`INSERT INTO finding_retests(id,tenant_id,engagement_id,finding_id,outcome,tester) VALUES($1,$2,$3,$4,'still_open','alice')`, []any{ids["finding_retests"], tenantA, engagementA, findingA}},
		{`INSERT INTO imported_sboms(id,tenant_id,engagement_id,spec_version,target_ref,component_count,sha256,raw_json) VALUES($1,$2,$3,'1.5','a',1,$1,'{}')`, []any{ids["imported_sboms"], tenantA, engagementA}},
		{`INSERT INTO writeup_drafts(id,tenant_id,engagement_id,finding_id,state) VALUES($1,$2,$3,$4,'proposed')`, []any{ids["writeup_drafts"], tenantA, engagementA, findingA}},
		{`INSERT INTO jobs(id,tenant_id,kind,payload) VALUES($1,$2,'sca','{}')`, []any{ids["jobs"], tenantA}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed graph: %v", err)
		}
	}

	role := uniqueProbeRole(t, "asset_graph_runtime")
	for _, statement := range []string{
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='` + role + `') THEN EXECUTE 'DROP OWNED BY ` + role + `'; EXECUTE 'DROP ROLE ` + role + `'; END IF; END $$`,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT,INSERT,UPDATE ON engagements,scope_targets,findings,evidence,finding_comments,finding_retests,imported_sboms,writeup_drafts,jobs TO ` + role,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("role setup: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})

	underRole := func(tenant *string, fn func(pgx.Tx) error) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if tenant != nil {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, *tenant); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
			return err
		}
		return fn(tx)
	}
	countKnown := func(tenant *string, table, id string) int {
		var count int
		if err := underRole(tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE id=$1`, id).Scan(&count)
		}); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return count
	}
	for table, id := range ids {
		if got := countKnown(&tenantA, table, id); got != 1 {
			t.Fatalf("tenant A %s count=%d, want 1", table, got)
		}
		if got := countKnown(&tenantB, table, id); got != 0 {
			t.Fatalf("tenant B accessed tenant A %s by known ID", table)
		}
		if got := countKnown(nil, table, id); got != 0 {
			t.Fatalf("unset tenant accessed %s", table)
		}
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	txA, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txA.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := txA.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
		t.Fatal(err)
	}
	var visible int
	if err := txA.QueryRow(ctx, `SELECT count(*) FROM engagements WHERE id=$1`, engagementA).Scan(&visible); err != nil || visible != 1 {
		t.Fatalf("tenant transaction count=%d err=%v", visible, err)
	}
	if err := txA.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	txUnset, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer txUnset.Rollback(ctx)
	if _, err := txUnset.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
		t.Fatal(err)
	}
	if err := txUnset.QueryRow(ctx, `SELECT count(*) FROM engagements WHERE id=$1`, engagementA).Scan(&visible); err != nil || visible != 0 {
		t.Fatalf("reused unscoped connection count=%d err=%v", visible, err)
	}

	if err := underRole(&tenantB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE engagements SET name='stolen' WHERE id=$1`, engagementA)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Fatalf("tenant B updated tenant A Engagement by known ID")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	crossErr := underRole(&tenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($1,$2,$3,'cross')`, prefix+"-cross", tenantB, engagementA)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(crossErr, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("cross-tenant graph reference must fail with FK violation, got %v", crossErr)
	}

	for table := range ids {
		var forced bool
		if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname=$1`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("FORCE RLS %s=%v err=%v", table, forced, err)
		}
	}
}
