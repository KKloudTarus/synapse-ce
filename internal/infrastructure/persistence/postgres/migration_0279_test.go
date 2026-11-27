package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestMigration0279HashSchemeHasNoDefault (#1703): after 0279 a writer that omits hash_scheme fails on NOT
// NULL instead of stamping its row legacy.
func TestMigration0279HashSchemeHasNoDefault(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	for _, table := range []string{"audit_log", "evidence"} {
		var def *string
		if err := pool.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name = 'hash_scheme'`, table).Scan(&def); err != nil {
			t.Fatalf("%s: read column: %v", table, err)
		}
		if def != nil {
			t.Errorf("%s.hash_scheme default = %q, want none", table, *def)
		}
	}
	target := "hash-scheme-no-default-" + time.Now().UTC().Format("150405.000000000")
	cleanupAuditRows(t, pool, target)
	_, err := pool.Exec(ctx, `INSERT INTO audit_log (tenant_id, actor, action, target, created_at, hash, previous_hash)
		VALUES ('', 'op', 'no.scheme', $1, now(), 'h', '')`, target)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23502" {
		t.Fatalf("insert without hash_scheme: err = %v, want a NOT NULL violation (23502)", err)
	}
}
