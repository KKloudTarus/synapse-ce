package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
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
		{uuid.New().String(), "sast", "sast:go:sql-injection:main.go:42", "go:sql-injection"},
		{uuid.New().String(), "sast", "sast:go:sql-injection:C:\\project\\main.go:42", "go:sql-injection"},
		{uuid.New().String(), "secret", "secret:aws-key:file.txt:1", "aws-key"},
		{uuid.New().String(), "misconfig", "misconfig:tf.s3.public:main.tf:10", "tf.s3.public"},
		{uuid.New().String(), "quality", "quality:quality-duplicated-block:src/foo.js:12", "quality-duplicated-block"},
		{uuid.New().String(), "reliability", "reliability:reliability-empty-catch:test.java:5", "reliability-empty-catch"},
		{uuid.New().String(), "sast", "sast:my:weird:rule:name:path/file.go:1", "my:weird:rule:name"},
		{uuid.New().String(), "sca", "vuln:CVE-1:pkg:1", ""},
		{uuid.New().String(), "sast", "sast:bad-format", ""}, // Does not match regex
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
	err = pool.QueryRow(ctx, "SELECT rule_key FROM findings WHERE id=$1", fixtures[0].id).Scan(nil)
	if err == nil {
		t.Error("rule_key column still exists after Down")
	}

	// 6. Apply Up again
	if err := goose.UpTo(db, ".", 44); err != nil {
		t.Fatalf("goose up to 44 (second time): %v", err)
	}
}
