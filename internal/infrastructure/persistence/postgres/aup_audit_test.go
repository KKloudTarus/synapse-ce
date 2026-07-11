package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAUPStoreAndAuditLog(t *testing.T) {
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
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// --- AUP acceptance ---
	ver := "test-" + randHex(t)
	store := NewAUPStore(pool)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM aup_acceptances WHERE policy_version=$1", ver) })

	if ok, err := store.Accepted(ctx, ver); err != nil || ok {
		t.Fatalf("Accepted before save = %v (err %v), want false", ok, err)
	}
	acc := aup.Acceptance{Version: ver, Actor: "operator", AcceptedAt: time.Now().UTC()}
	if err := store.Save(ctx, acc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Save(ctx, acc); err != nil { // idempotent re-accept
		t.Fatalf("Save (idempotent): %v", err)
	}
	if ok, err := store.Accepted(ctx, ver); err != nil || !ok {
		t.Fatalf("Accepted after save = %v (err %v), want true", ok, err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM aup_acceptances WHERE policy_version=$1", ver).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("want 1 acceptance row (idempotent), got %d", n)
	}

	// --- append-only audit ---
	// audit_log is DB-enforced append-only (migration 0033: UPDATE/DELETE/TRUNCATE raise), so
	// there is no cleanup – the test uses a unique action per run (randHex) and filters reads by
	// it, so accumulated rows from prior runs are harmless.
	action := "test.action-" + randHex(t)
	log := NewAuditLog(pool)

	if err := log.Record(ctx, ports.AuditEntry{
		Actor: "operator", Action: action, Target: "engagement-1",
		Metadata: map[string]string{"kind": "local"}, At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	var actor, target, meta string
	if err := pool.QueryRow(ctx,
		"SELECT actor, target, metadata::text FROM audit_log WHERE action=$1", action).Scan(&actor, &target, &meta); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if actor != "operator" || target != "engagement-1" || !strings.Contains(meta, "local") {
		t.Errorf("audit entry = actor=%s target=%s meta=%s", actor, target, meta)
	}
}
