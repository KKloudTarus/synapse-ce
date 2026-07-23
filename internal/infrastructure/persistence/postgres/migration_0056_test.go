package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0056BackfillsOnlyCanonicalRelativePaths(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("initial migrate up: %v", err)
	}
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatalf("goose open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose set dialect: %v", err)
	}
	if err := goose.DownTo(db, ".", 55); err != nil {
		t.Fatalf("goose down to 55: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	tenantID, projectID := uuid.New().String(), uuid.New().String()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'migration-0056')`, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding) VALUES ($1, $2, 'migration-0056', $1, '{}')`, projectID, tenantID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id=$1", projectID)
		_, _ = pool.Exec(ctx, "DELETE FROM tenants WHERE id=$1", tenantID)
	})

	paths := []struct {
		path     string
		location string
		want     *string
	}{{"src/main.go", "src/main.go:7", stringPtr("src/main.go")}, {"/etc/passwd", "/etc/passwd:7", nil}, {"./main.go", "./main.go:7", nil}, {"../main.go", "../main.go:7", nil}, {"src/stale.go", "src/current.go:7", nil}}
	now := time.Now().UTC()
	for index, fixture := range paths {
		issueID, hotspotID := uuid.New().String(), uuid.New().String()
		if _, err := pool.Exec(ctx, `INSERT INTO project_issues
			(id, tenant_id, project_id, issue_key, finding_identity, rule_key, issue_type, title, description, severity, finding_kind, file, location, status, version, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$4,'rule','bug','title','description','medium','sast',$5,$6,'open',1,'analysis','analysis',$7,$7,$7,$7)`, issueID, tenantID, projectID, "issue-"+issueID, fixture.path, fixture.location, now); err != nil {
			t.Fatalf("insert issue %d: %v", index, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO project_hotspots
			(id, tenant_id, project_id, hotspot_key, finding_identity, rule_key, title, description, severity, finding_kind, location, status, version, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$4,'rule','title','description','medium','sast',$5,'to_review',1,'analysis','analysis',$6,$6,$6,$6)`, hotspotID, tenantID, projectID, "hotspot-"+hotspotID, fixture.location, now); err != nil {
			t.Fatalf("insert hotspot %d: %v", index, err)
		}
		paths[index].path = issueID + ":" + hotspotID
	}

	if err := goose.UpTo(db, ".", 56); err != nil {
		t.Fatalf("goose up to 56: %v", err)
	}
	for index, fixture := range paths {
		ids := splitFixtureIDs(fixture.path)
		for _, query := range []struct {
			table string
			id    string
		}{{"project_issues", ids[0]}, {"project_hotspots", ids[1]}} {
			var got *string
			if err := pool.QueryRow(ctx, "SELECT source_file FROM "+query.table+" WHERE id=$1", query.id).Scan(&got); err != nil {
				t.Fatalf("query %s %d: %v", query.table, index, err)
			}
			if (got == nil) != (fixture.want == nil) || got != nil && *got != *fixture.want {
				t.Errorf("%s fixture %d source_file=%v, want %v", query.table, index, got, fixture.want)
			}
		}
	}
	if err := goose.DownTo(db, ".", 55); err != nil {
		t.Fatalf("goose down to 55: %v", err)
	}
	var value *string
	err = pool.QueryRow(ctx, "SELECT source_file FROM project_issues LIMIT 1").Scan(&value)
	if pgErr, ok := err.(*pgconn.PgError); !ok || pgErr.Code != "42703" {
		t.Fatalf("source_file exists after down: %T %v", err, err)
	}
	if err := goose.UpTo(db, ".", 56); err != nil {
		t.Fatalf("goose up to 56 again: %v", err)
	}
}

func stringPtr(value string) *string { return &value }

func splitFixtureIDs(value string) [2]string {
	for index := range value {
		if value[index] == ':' {
			return [2]string{value[:index], value[index+1:]}
		}
	}
	return [2]string{}
}
