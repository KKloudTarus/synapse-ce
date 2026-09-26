package postgres

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

// TestMigration0181DisablesRulesThatCanNeverMatch seeds rules at version 180, applies 0181 and
// checks that only engagement-scoped rules for event types without an engagement were disabled.
func TestMigration0181DisablesRulesThatCanNeverMatch(t *testing.T) {
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	dsn := isolatedMigrationDSN(t, sharedDSN, "0181")
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := openLockedGooseDB(t, dsn)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.DownTo(db, ".", 180); err != nil {
		t.Fatalf("down to 180: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	const tenant = "t-migration-0181"
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1)`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	seed := []struct {
		id, event, engagements string
		enabled                bool
	}{
		{"gate-scoped", "quality_gate.failed", `["eng-1"]`, true},
		{"offline-scoped-disabled", "fleet.agent.offline", `["eng-2"]`, false},
		{"gate-unscoped", "quality_gate.failed", `[]`, true},
		{"scan-scoped", "scan.completed", `["eng-1"]`, true},
	}
	for _, r := range seed {
		if _, err := pool.Exec(ctx, `INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,engagement_ids,created_at,updated_at)
			VALUES($1,$2,$2,$3,$4,$5::jsonb,$6,$6)`, tenant, r.id, r.enabled, r.event, r.engagements, created); err != nil {
			t.Fatalf("seed rule %s: %v", r.id, err)
		}
	}

	if err := goose.UpTo(db, ".", 181); err != nil {
		t.Fatalf("up to 181: %v", err)
	}

	want := map[string]struct {
		enabled  bool
		reason   string
		revision int
		engs     []string
	}{
		"gate-scoped":             {false, notification.DisabledEngagementFilterUnsupported, 2, []string{"eng-1"}},
		"offline-scoped-disabled": {false, notification.DisabledEngagementFilterUnsupported, 2, []string{"eng-2"}},
		"gate-unscoped":           {true, "", 1, []string{}},
		"scan-scoped":             {true, "", 1, []string{"eng-1"}},
	}
	for id, w := range want {
		var enabled bool
		var reason string
		var revision int
		var raw []byte
		var updated time.Time
		if err := pool.QueryRow(ctx, `SELECT enabled,disabled_reason,revision,engagement_ids,updated_at FROM notification_rules WHERE tenant_id=$1 AND id=$2`, tenant, id).
			Scan(&enabled, &reason, &revision, &raw, &updated); err != nil {
			t.Fatalf("read rule %s: %v", id, err)
		}
		var engs []string
		if err := json.Unmarshal(raw, &engs); err != nil {
			t.Fatalf("decode engagements of %s: %v", id, err)
		}
		if enabled != w.enabled || reason != w.reason || revision != w.revision || len(engs) != len(w.engs) || len(engs) > 0 && engs[0] != w.engs[0] {
			t.Fatalf("rule %s = enabled:%v reason:%q revision:%d engagements:%v, want %+v", id, enabled, reason, revision, engs, w)
		}
		if (w.reason != "") != updated.After(created) {
			t.Fatalf("rule %s updated_at = %v, changed = %v", id, updated, w.reason != "")
		}
	}

	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid='notification_rules'::regclass`).Scan(&forced); err != nil {
		t.Fatalf("inspect RLS: %v", err)
	}
	if !forced {
		t.Fatal("notification_rules lost FORCE ROW LEVEL SECURITY")
	}

	if err := goose.DownTo(db, ".", 180); err != nil {
		t.Fatalf("down to 180 after apply: %v", err)
	}
	if err := goose.Up(db, "."); err != nil {
		t.Fatalf("up after down: %v", err)
	}
}
