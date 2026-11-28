package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestClosureAuditKeysScopedByCycleAndActor (#1733): on the tenant chain the audit log deduplicates on
// (tenant, action, idempotency_key). Two closes in one tenant that reuse a client's key must both record
// when they name different cycles or actors, and a retry of one of them must add no row. It runs as a
// runtime role with row-level security active, the path production takes.
func TestClosureAuditKeysScopedByCycleAndActor(t *testing.T) {
	const tenant = "closure-key-tenant"
	pool, _ := ownershipMigrationDatabase(t, 282, 0, func(db *sql.DB) {
		if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES ($1,$1)`, tenant); err != nil {
			t.Fatal(err)
		}
	})
	ctx := context.Background()
	log := NewAuditLog(pool)
	tenantCtx := shared.WithTenant(ctx, tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	const action = "assessment_cycle.closed"
	record := func(cycle, actor, key string) error {
		return log.Record(tenantCtx, ports.AuditEntry{Actor: actor, Action: action, Target: cycle, At: at,
			Metadata: map[string]string{"tenant_id": tenant, "cycle_version": "2", "idempotency_key": cycle + ":" + actor + ":" + key}})
	}
	// The same client key, on two cycles by two actors: both commits record.
	if err := record("cycle-a", "alice", "close-1"); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := record("cycle-b", "bob", "close-1"); err != nil {
		t.Fatalf("second close with the same client key: %v", err)
	}
	// A retry of the first close with the same raw entry adds no row.
	if err := record("cycle-a", "alice", "close-1"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	// The unscoped key, as the writer recorded it before #1733, conflicts on the second cycle.
	err := log.Record(tenantCtx, ports.AuditEntry{Actor: "carol", Action: action, Target: "cycle-c", At: at,
		Metadata: map[string]string{"idempotency_key": "close-1"}})
	if err != nil {
		t.Fatalf("first raw key: %v", err)
	}
	if err := log.Record(tenantCtx, ports.AuditEntry{Actor: "dave", Action: action, Target: "cycle-d", At: at,
		Metadata: map[string]string{"idempotency_key": "close-1"}}); err == nil {
		t.Fatal("an unscoped client key reused on another cycle must conflict; scoping is what avoids it")
	}
	var rows int
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1 AND target LIKE 'cycle-_'`, action).Scan(&rows)
	}); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Fatalf("audit rows = %d, want 3 (cycle-a, cycle-b, cycle-c; the retry deduplicated, cycle-d refused)", rows)
	}
}
