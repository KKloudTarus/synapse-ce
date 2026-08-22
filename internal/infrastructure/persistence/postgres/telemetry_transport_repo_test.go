package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTelemetryTransportRepository(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenant := shared.ID("ttrans-" + id)
	other := shared.ID("ttrans-other-" + id)
	for _, tn := range []shared.ID{tenant, other} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tn.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tbl := range []string{"telemetry_batch_events", "telemetry_stream_positions"} {
			for _, tn := range []shared.ID{tenant, other} {
				_, _ = pool.Exec(bg, `DELETE FROM `+tbl+` WHERE tenant_id=$1`, tn.String())
			}
		}
		for _, tn := range []shared.ID{tenant, other} {
			_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tn.String())
		}
	})

	repo := NewTelemetryTransportRepository(pool)
	tctx := shared.WithTenant(ctx, tenant)
	now := time.Now().UTC()
	stream := shared.ID("stream-" + id)
	agentA := shared.ID("agent-a-" + id)
	agentB := shared.ID("agent-b-" + id)

	// Zero state for an unseen (agent, stream, epoch): Version 0.
	if st, err := repo.StreamState(tctx, agentA, stream, 1); err != nil || st.Contiguous != 0 || len(st.Pending) != 0 || st.Version != 0 {
		t.Fatalf("unseen stream must be zero state: %+v err=%v", st, err)
	}

	// Save (version 0 → insert) + reload; the stored version advances to 1.
	want := ports.TelemetryStreamState{AgentID: agentA, StreamID: stream, Epoch: 1, Contiguous: 3, Pending: []uint64{5, 7}, UpdatedAt: now}
	if err := repo.SaveStreamState(tctx, want); err != nil {
		t.Fatalf("save stream state: %v", err)
	}
	got, err := repo.StreamState(tctx, agentA, stream, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.Contiguous != 3 || len(got.Pending) != 2 || got.Pending[0] != 5 || got.Pending[1] != 7 || got.Version != 1 {
		t.Fatalf("reloaded state mismatch: %+v", got)
	}

	// Gaps are DERIVED from the snapshot: contiguous=3, pending={5,7} ⇒ holes [4,4] and [6,6].
	gaps, err := repo.ListGaps(tctx, agentA, stream)
	if err != nil || len(gaps) != 2 || gaps[0].FromSequence != 4 || gaps[0].ToSequence != 4 || gaps[1].FromSequence != 6 || gaps[1].ToSequence != 6 {
		t.Fatalf("want derived gaps [4,4],[6,6], got %+v err=%v", gaps, err)
	}

	// Optimistic concurrency: a save carrying a STALE version must be rejected with ErrConflict.
	stale := got
	stale.Version = 0 // pretend we still hold the pre-insert version
	stale.Contiguous, stale.Pending = 99, nil
	if err := repo.SaveStreamState(tctx, stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale-version save must conflict, got %v", err)
	}
	// The CAS with the CURRENT version wins and clears the pending set (so the derived gaps disappear).
	got.Contiguous, got.Pending = 7, nil
	if err := repo.SaveStreamState(tctx, got); err != nil {
		t.Fatal(err)
	}
	if reloaded, _ := repo.StreamState(tctx, agentA, stream, 1); reloaded.Contiguous != 7 || len(reloaded.Pending) != 0 || reloaded.Version != 2 {
		t.Fatalf("CAS did not advance state+version: %+v", reloaded)
	}
	if gaps, _ := repo.ListGaps(tctx, agentA, stream); len(gaps) != 0 {
		t.Fatalf("a fully-contiguous stream must have no derived gaps, got %+v", gaps)
	}

	// MaxEpoch reflects the highest epoch with state.
	if err := repo.SaveStreamState(tctx, ports.TelemetryStreamState{AgentID: agentA, StreamID: stream, Epoch: 4, Contiguous: 1, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if max, _ := repo.MaxEpoch(tctx, agentA, stream); max != 4 {
		t.Fatalf("MaxEpoch = %d, want 4", max)
	}

	// Batch events: ingest + idempotent + count.
	batch := ports.TelemetryEventBatch{
		AgentID: agentA, StreamID: stream, AssetID: "as", Epoch: 1, Sequence: 1, SchemaVersion: 1,
		Events: []ports.StoredTelemetryEvent{
			{EventID: "e1", Class: detection.ClassProcess, Digest: "d1", Payload: []byte("p1"), ObservedAt: now},
			{EventID: "e2", Class: detection.ClassNetwork, Digest: "d2", Payload: []byte("p2"), ObservedAt: now},
		},
	}
	if n, err := repo.IngestBatchEvents(tctx, batch); err != nil || n != 2 {
		t.Fatalf("first ingest must store 2, got %d err=%v", n, err)
	}
	if n, err := repo.IngestBatchEvents(tctx, batch); err != nil || n != 0 {
		t.Fatalf("re-ingest must store 0 (idempotent), got %d err=%v", n, err)
	}
	if n, _ := repo.CountBatchEvents(tctx, agentA, stream, 1, 1); n != 2 {
		t.Fatalf("CountBatchEvents = %d, want 2", n)
	}

	// Cross-agent isolation: a DIFFERENT agent using the SAME StreamID has its OWN stream space within the
	// tenant — it sees agentA's state as zero and cannot read agentA's events. This is the HIGH-2 fix.
	if st, _ := repo.StreamState(tctx, agentB, stream, 1); st.Contiguous != 0 || st.Version != 0 {
		t.Fatalf("sibling agent must see zero state for the same stream id, got %+v", st)
	}
	if max, _ := repo.MaxEpoch(tctx, agentB, stream); max != 0 {
		t.Fatalf("sibling agent MaxEpoch must be 0, got %d", max)
	}
	if n, _ := repo.CountBatchEvents(tctx, agentB, stream, 1, 1); n != 0 {
		t.Fatalf("sibling agent must not see agentA's events, got %d", n)
	}

	// RLS isolation: the other tenant sees none of this stream's transport rows.
	octx := shared.WithTenant(ctx, other)
	if gaps, _ := repo.ListGaps(octx, agentA, stream); len(gaps) != 0 {
		t.Fatalf("cross-tenant must not see gaps, got %d", len(gaps))
	}
	if n, _ := repo.CountBatchEvents(octx, agentA, stream, 1, 1); n != 0 {
		t.Fatalf("cross-tenant must not see events, got %d", n)
	}
	if st, _ := repo.StreamState(octx, agentA, stream, 1); st.Contiguous != 0 {
		t.Fatalf("cross-tenant must not see stream state, got contiguous %d", st.Contiguous)
	}
	if max, _ := repo.MaxEpoch(octx, agentA, stream); max != 0 {
		t.Fatalf("cross-tenant MaxEpoch must be 0, got %d", max)
	}
}
