package postgres

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestScannedImageStore(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('ta','A'),('tb','B') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM scanned_image WHERE tenant_id IN ('ta','tb','default')`)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ('ta','tb')`)
	})

	s := NewScannedImageStore(pool)
	now := time.Now().UTC().Truncate(time.Second)

	// Mark + idempotent re-mark.
	if err := s.MarkScanned(ctx, "ta", "sha256:aaa", now); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if err := s.MarkScanned(ctx, "ta", "sha256:aaa", now.Add(time.Hour)); err != nil {
		t.Fatalf("re-mark: %v", err)
	}
	if err := s.MarkScanned(ctx, "ta", "sha256:bbb", now); err != nil {
		t.Fatalf("mark bbb: %v", err)
	}
	got, err := s.ScannedDigests(ctx, "ta")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 || !got["sha256:aaa"] || !got["sha256:bbb"] {
		t.Fatalf("expected {aaa,bbb}, got %v", got)
	}

	// Tenant scoping: tb does not see ta's digests.
	_ = s.MarkScanned(ctx, "tb", "sha256:ccc", now)
	tb, _ := s.ScannedDigests(ctx, "tb")
	if tb["sha256:aaa"] || !tb["sha256:ccc"] {
		t.Fatalf("tenant scoping failed: %v", tb)
	}

	// Empty tenant normalizes to 'default' (seeded by 0058) — records + reads land together.
	if err := s.MarkScanned(ctx, "", "sha256:ddd", now); err != nil {
		t.Fatalf("mark empty tenant: %v", err)
	}
	def, err := s.ScannedDigests(ctx, "default")
	if err != nil {
		t.Fatalf("query default: %v", err)
	}
	if !def["sha256:ddd"] {
		t.Fatalf("empty tenant must normalize to 'default', got %v", def)
	}
}
