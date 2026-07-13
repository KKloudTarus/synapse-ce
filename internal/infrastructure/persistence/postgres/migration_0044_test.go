package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0044(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()

	// 1. Connect to DB and migrate DOWN to 43 to test 44 Up
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("initial migrate up: %v", err)
	}

	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatalf("goose open db: %v", err)
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose set dialect: %v", err)
	}

	if err := goose.DownTo(db, ".", 43); err != nil {
		t.Fatalf("goose down to 43: %v", err)
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	eidString := uuid.New().String()
	eid := shared.ID(eidString)
	e, err := engagement.New(eid, "", "test", "", time.Now().UTC())
	if err != nil {
		t.Fatalf("new engagement: %v", err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatalf("insert engagement: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM findings WHERE engagement_id=$1", eidString)
		_, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", eidString)
	})

	// 2. Insert the fixture matrix (legacy rows without rule_key column since we are at v43)
	fixtures := []struct {
		id       string
		kind     string
		dedupKey string
		wantRule string
	}{
		{uuid.New().String(), "sast", "sast:sql-injection:src/a.go:10", "sql-injection"},
		{uuid.New().String(), "secret", "secret:google-api-key:src/a.go:11", "google-api-key"},
		{uuid.New().String(), "misconfig", "misconfig:terraform-open-egress:main.tf:12", "terraform-open-egress"},
		{uuid.New().String(), "quality", "quality:quality-high-complexity:src/a.go:13", "quality-high-complexity"},
		{uuid.New().String(), "reliability", "reliability:reliability-empty-catch:src/A.java:14", "reliability-empty-catch"},
		{uuid.New().String(), "sast", "sast:sql-injection:C:\\src\\main.go:42", "sql-injection"},
		{uuid.New().String(), "sast", "secret:google-api-key:file.go:1", ""}, // Prefix mismatch
		{uuid.New().String(), "sast", "sast::file.go:1", ""},                 // Empty rule
		{uuid.New().String(), "sast", "sast:rule::1", ""},                    // Empty path
		{uuid.New().String(), "sast", "sast:rule:file.go:not-a-number", ""},  // Non-numeric line
		{uuid.New().String(), "sast", "sast:go:sql-injection:file.go:1", ""}, // Colons in rule
		{uuid.New().String(), "sca", "sca:some-rule:file.go:1", ""},          // Unsupported kind
		{uuid.New().String(), "manual", "manual:some-rule:file.go:1", ""},
		{uuid.New().String(), "dast", "dast:some-rule:file.go:1", ""},
		{uuid.New().String(), "", "sast:sql-injection:src/a.go:11", ""}, // Empty kind
		{uuid.New().String(), "sast", "arbitrary malformed string", ""},
	}

	now := time.Now().UTC()
	for _, f := range fixtures {
		_, err := pool.Exec(ctx,
			`INSERT INTO findings (id, tenant_id, engagement_id, title, description, severity, cvss_vector, cwe, status, evidence_score, dedup_key, kev, risk_score, created_at, updated_at, sources, confidence, class, scope, reachability, impact, priority, kind, assignee, version, proposed_by, class_reachability)
			 VALUES ($1, '', $2, 'test', 'desc', 'medium', '', '', 'open', 0, $3, false, 0.0, $4, $4, '', '', 'third_party', 'unknown', 'unknown', '', 3, $5, '', 1, '', '')`,
			f.id, eidString, f.dedupKey, now, f.kind)
		if err != nil {
			t.Fatalf("insert fixture %s: %v", f.id, err)
		}
	}

	// 3. Apply 0044 Up
	if err := goose.UpTo(db, ".", 44); err != nil {
		t.Fatalf("goose up to 44: %v", err)
	}

	// 4. Assert row states
	for _, f := range fixtures {
		var gotRule string
		if err := pool.QueryRow(ctx, "SELECT rule_key FROM findings WHERE id=$1", f.id).Scan(&gotRule); err != nil {
			t.Errorf("fixture %s not found: %v", f.id, err)
			continue
		}
		if gotRule != f.wantRule {
			t.Errorf("fixture %s (dedup: %s): got rule_key %q, want %q", f.id, f.dedupKey, gotRule, f.wantRule)
		}
	}

	// 5. Apply Down
	if err := goose.DownTo(db, ".", 43); err != nil {
		t.Fatalf("goose down to 43: %v", err)
	}

	// Assert rule_key is gone
	var scanVal string
	err = pool.QueryRow(ctx, "SELECT rule_key FROM findings WHERE id=$1", fixtures[0].id).Scan(&scanVal)
	if err == nil {
		t.Error("rule_key column still exists after Down")
	} else if pgErr, ok := err.(*pgconn.PgError); ok {
		if pgErr.Code != "42703" { // undefined_column
			t.Errorf("expected undefined_column error, got: %v", pgErr.Code)
		}
	} else {
		t.Errorf("expected pgx error, got: %T %v", err, err)
	}

	// 6. Apply Up again
	if err := goose.UpTo(db, ".", 44); err != nil {
		t.Fatalf("goose up to 44 (second time): %v", err)
	}

	// Assert column exists and backfill is correct again
	for _, f := range fixtures {
		var gotRule string
		if err := pool.QueryRow(ctx, "SELECT rule_key FROM findings WHERE id=$1", f.id).Scan(&gotRule); err != nil {
			t.Errorf("fixture %s not found on second up: %v", f.id, err)
			continue
		}
		if gotRule != f.wantRule {
			t.Errorf("fixture %s (dedup: %s): got rule_key %q, want %q on second up", f.id, f.dedupKey, gotRule, f.wantRule)
		}
	}
}
