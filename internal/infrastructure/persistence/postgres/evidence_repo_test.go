package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestPostgresEvidenceForkGuard covers that the unique(engagement, previous_hash)
// index rejects a second child for the same parent as ErrConflict, so concurrent
// writers (API + worker) can never fork the hash chain. Gated on SYNAPSE_TEST_DB_DSN.
func TestPostgresEvidenceForkGuard(t *testing.T) {
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
	// evidence is DB-enforced append-only (migration 0033) – no TRUNCATE. Use a fresh
	// engagement id per run so the per-engagement fork-guard starts from an empty chain and
	// accumulated rows from prior runs are harmless.
	eng := "eng-" + randHex(t)
	if _, err := pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name) VALUES ($1, '', 'test') ON CONFLICT (id) DO NOTHING`, eng); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	store := NewEvidenceStore(pool)

	link := func(id, prev, hash string) evidence.Evidence {
		return evidence.Evidence{ID: shared.ID(id + eng), EngagementID: shared.ID(eng), Kind: "k", Content: []byte(id), PreviousHash: prev, Hash: hash, CreatedBy: "op", CreatedAt: time.Unix(1, 0).UTC()}
	}
	// Genesis (previous_hash="").
	if err := store.Append(ctx, []evidence.Evidence{link("a", "", "hashA")}); err != nil {
		t.Fatalf("append genesis: %v", err)
	}
	// A SECOND child of the same parent (previous_hash="") must be rejected as a fork.
	if err := store.Append(ctx, []evidence.Evidence{link("b", "", "hashB")}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a second child of the same parent must be ErrConflict, got %v", err)
	}
	// A proper child (previous_hash=hashA) is accepted.
	if err := store.Append(ctx, []evidence.Evidence{link("c", "hashA", "hashC")}); err != nil {
		t.Fatalf("append linear child: %v", err)
	}
}

// TestPostgresEvidenceVerifyRoundTrip covers the re-audit hash change: a chain sealed with
// created_by/created_at bound into the hash must still VerifyChain after a Postgres
// round-trip (the hash truncates the timestamp to µs to match timestamptz precision).
func TestPostgresEvidenceVerifyRoundTrip(t *testing.T) {
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
	// Append-only (0033): no TRUNCATE; isolate by a fresh engagement id per run.
	eng := "engRT-" + randHex(t)
	_, _ = pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name) VALUES ($1,'','rt') ON CONFLICT (id) DO NOTHING`, eng)
	store := NewEvidenceStore(pool)

	now := time.Now() // nanosecond precision – must survive the round-trip via µs truncation
	prev := ""
	for i := 0; i < 3; i++ {
		e := evidence.Evidence{
			ID: shared.ID("rt" + string(rune('a'+i)) + eng), EngagementID: shared.ID(eng), Kind: "scan",
			Content: []byte{byte(i)}, PreviousHash: prev, CreatedBy: "op", CreatedAt: now.Add(time.Duration(i) * time.Second),
		}.Seal()
		if err := store.Append(ctx, []evidence.Evidence{e}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		prev = e.Hash
	}
	got, err := store.ListByEngagement(ctx, shared.ID(eng))
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.VerifyChain(got); err != nil {
		t.Fatalf("chain must verify after a Postgres round-trip (µs precision): %v", err)
	}
	// And a post-round-trip attribution rewrite must break it.
	got[1].CreatedBy = "attacker"
	if err := evidence.VerifyChain(got); err == nil {
		t.Fatal("a rewritten created_by must break the round-tripped chain")
	}
}
