package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAppendOnlyEnforcement proves migration 0033 makes the evidence + audit custody tables
// DB-enforced append-only: UPDATE/DELETE/TRUNCATE all raise, so a tail-truncation or row-edit
// is impossible in-band, not merely tamper-evident. Gated on SYNAPSE_TEST_DB_DSN.
func TestAppendOnlyEnforcement(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	// The repositories run every statement through WithTenant, which refuses an unbound tenant so a
	// query can never silently escape RLS. Fixtures must therefore state the tenant they act as,
	// exactly like the HTTP middleware and the worker do.
	ctx = shared.WithTenant(ctx, "default")
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	eng := "eng-ao-" + randHex(t)
	if _, err := pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name) VALUES ($1,'default','ao') ON CONFLICT (id) DO NOTHING`, eng); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	ev := evidence.Evidence{ID: shared.ID("ao-" + eng), EngagementID: shared.ID(eng), Kind: "k", Content: []byte("x"), PreviousHash: "", Hash: "h-" + eng, CreatedBy: "op", CreatedAt: time.Unix(1, 0).UTC()}
	if err := NewEvidenceStore(pool).Append(ctx, []evidence.Evidence{ev}); err != nil {
		t.Fatalf("seal evidence: %v", err)
	}

	rejects := func(label, q string, args ...any) {
		if _, err := pool.Exec(ctx, q, args...); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s must be rejected as append-only, got %v", label, err)
		}
	}
	// refused accepts EITHER mechanism. A plain TRUNCATE can be stopped by a foreign key from any table
	// referencing evidence before the trigger is reached -- which is incidental protection: it depends on
	// some other table happening to reference this one, and it disappears the day that table does not.
	refused := func(label, q string, args ...any) {
		if _, err := pool.Exec(ctx, q, args...); err == nil {
			t.Errorf("%s must be refused, got nil", label)
		}
	}
	rejects("DELETE evidence", `DELETE FROM evidence WHERE id=$1`, ev.ID.String())
	rejects("UPDATE evidence", `UPDATE evidence SET content='y' WHERE id=$1`, ev.ID.String())
	refused("TRUNCATE evidence", `TRUNCATE evidence`)
	// CASCADE is the variant that matters, and the one a foreign key cannot stop: it truncates the
	// referencing tables too, so the FK objection evaporates and only the append-only trigger is left.
	// Asserting on the trigger's own message keeps this test measuring the guarantee rather than a
	// side effect of the current schema.
	rejects("TRUNCATE evidence CASCADE", `TRUNCATE evidence CASCADE`)

	action := "ao.action-" + randHex(t)
	t.Cleanup(func() {
		bg := context.Background()
		conn, err := pool.Acquire(bg)
		if err != nil {
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(bg, `SET session_replication_role = replica`); err != nil {
			return
		}
		defer conn.Exec(bg, `SET session_replication_role = origin`)
		_, _ = conn.Exec(bg, `DELETE FROM evidence WHERE id=$1`, ev.ID.String())
		_, _ = conn.Exec(bg, `DELETE FROM engagements WHERE id=$1`, eng)
		_, _ = conn.Exec(bg, `DELETE FROM audit_log WHERE action=$1`, action)
	})
	if err := NewAuditLog(pool).Record(ctx, ports.AuditEntry{Actor: "op", Action: action, Target: "t", At: time.Now().UTC()}); err != nil {
		t.Fatalf("record audit: %v", err)
	}
	rejects("DELETE audit_log", `DELETE FROM audit_log WHERE action=$1`, action)
	rejects("UPDATE audit_log", `UPDATE audit_log SET actor='x' WHERE action=$1`, action)
	rejects("TRUNCATE audit_log", `TRUNCATE audit_log`)
}

// TestTimestampStoreLatestHead proves LatestHead returns the most-recently-anchored head (the
// retained head used for tail-truncation detection), and ok=false when nothing is anchored.
func TestTimestampStoreLatestHead(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	store := NewTimestampStore(pool)
	eng := shared.ID("ts-" + randHex(t))

	if _, ok, err := store.LatestHead(ctx, "evidence", eng); err != nil || ok {
		t.Fatalf("empty chain must return ok=false, got ok=%v err=%v", ok, err)
	}
	tok := ports.TimestampToken{Authority: "tsa", Token: "t"}
	if err := store.Put(ctx, "evidence", eng, "head-a", tok); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "evidence", eng, "head-b", tok); err != nil {
		t.Fatal(err)
	}
	h, ok, err := store.LatestHead(ctx, "evidence", eng)
	if err != nil || !ok {
		t.Fatalf("LatestHead after anchors: ok=%v err=%v", ok, err)
	}
	if h != "head-b" { // newest by created_at, with head DESC as the deterministic tiebreak
		t.Fatalf("latest retained head = %q, want head-b", h)
	}
}

// TestAuditForkGuard proves the audit chain cannot fork (parity with the evidence chain): two
// rows can never claim the same parent hash. Direct inserts bypass the Record advisory lock to
// exercise the DB constraint itself.
func TestAuditForkGuard(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	parent := "parent-" + randHex(t)
	ins := `INSERT INTO audit_log (tenant_id, actor, action, target, hash, previous_hash) VALUES ('default','op','a','t',$1,$2)`
	if _, err := pool.Exec(ctx, ins, "h1-"+parent, parent); err != nil {
		t.Fatalf("first child of parent: %v", err)
	}
	if _, err := pool.Exec(ctx, ins, "h2-"+parent, parent); err == nil {
		t.Fatal("a SECOND row with the same previous_hash must violate the audit fork-guard")
	}
}
