package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0044(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()

	// Start from the current schema so this test is safe to run against the same CI database as the
	// rest of the integration suite. The cleanup below restores current HEAD again before returning.
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("initial migrate up: %v", err)
	}

	db := openLockedGooseDB(t, dsn)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose set dialect: %v", err)
	}
	// A migration test must not leave the shared integration database pinned to an old version even
	// when an assertion fails midway through the test.
	t.Cleanup(func() {
		if err := Migrate(context.Background(), dsn); err != nil {
			t.Errorf("restore latest schema: %v", err)
		}
	})

	if err := goose.DownTo(db, ".", 43); err != nil {
		t.Fatalf("goose down to 43: %v", err)
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	eidString := uuid.New().String()
	// Seed the v43 schema directly. Using the current EngagementRepository here is invalid because
	// repositories evolve with HEAD (for example project_id and business_asset_id were added after
	// v43), while this test intentionally exercises a historical schema.
	if _, err := pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name, client, status, created_at, updated_at)
		VALUES ($1, '', 'test', '', 'draft', $2, $2)`, eidString, time.Now().UTC()); err != nil {
		t.Fatalf("insert v43 engagement fixture: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM findings WHERE engagement_id=$1", eidString); err != nil {
			t.Errorf("cleanup findings: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM engagements WHERE id=$1", eidString); err != nil {
			t.Errorf("cleanup engagement: %v", err)
		}
	})

	// Insert the fixture matrix without rule_key, which does not exist at v43.
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

	if err := goose.UpTo(db, ".", 44); err != nil {
		t.Fatalf("goose up to 44: %v", err)
	}

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

	if err := goose.DownTo(db, ".", 43); err != nil {
		t.Fatalf("goose down to 43: %v", err)
	}

	// Assert the schema contract directly rather than depending on whether pgx reports an undefined
	// column as PgError or wraps it in a PrepareError.
	var ruleKeyExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema='public' AND table_name='findings' AND column_name='rule_key'
	)`).Scan(&ruleKeyExists); err != nil {
		t.Fatalf("inspect findings schema after down: %v", err)
	}
	if ruleKeyExists {
		t.Error("rule_key column still exists after Down")
	}

	if err := goose.UpTo(db, ".", 44); err != nil {
		t.Fatalf("goose up to 44 (second time): %v", err)
	}

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
