package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestMigration0272TimestampTokensAreAppendOnly pins the custody property the RFC-3161 anchor exists
// for. migrations/0033 names this table as the out-of-band detection for a trigger a superuser
// disabled; it was itself rewritable by the runtime role, so the detection could be erased by the
// same hand that forged the chain it was anchoring.
func TestMigration0272TimestampTokensAreAppendOnly(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	head := "anchor-" + time.Now().UTC().Format("150405.000000000")
	if _, err := pool.Exec(ctx, `INSERT INTO timestamp_tokens (chain, engagement_id, head, authority, token)
		VALUES ('audit','',$1,'https://tsa.example','dGVzdA==')`, head); err != nil {
		t.Fatalf("seed anchor: %v", err)
	}

	// Rewriting the anchored head is how a forged chain would be made to look anchored.
	_, err = pool.Exec(ctx, `UPDATE timestamp_tokens SET head='reforged' WHERE head=$1`, head)
	if err == nil {
		t.Fatal("an anchor was rewritten; the out-of-band detection is not append-only")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update refused for the wrong reason: %v", err)
	}

	// Deleting it is how the detection would be erased instead.
	_, err = pool.Exec(ctx, `DELETE FROM timestamp_tokens WHERE head=$1`, head)
	if err == nil {
		t.Fatal("an anchor was deleted; the out-of-band detection is not append-only")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("delete refused for the wrong reason: %v", err)
	}

	// The anchor is still there and still readable, so the store's own path is untouched.
	var n int
	if err := WithTenant(ctx, pool, "default", func(tx pgx.Tx) error { return nil }); err != nil {
		t.Fatalf("tenant probe: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM timestamp_tokens WHERE head=$1`, head).Scan(&n); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n != 1 {
		t.Fatalf("%d anchors after the refused mutations, want the original", n)
	}
}
