package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
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
		for _, tbl := range []string{"telemetry_batch_events", "telemetry_batch_commits", "telemetry_transport_gaps", "telemetry_stream_positions"} {
			for _, tn := range []shared.ID{tenant, other} {
				_, _ = pool.Exec(bg, `DELETE FROM `+tbl+` WHERE tenant_id=$1`, tn.String())
			}
		}
		for _, tn := range []shared.ID{tenant, other} {
			_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tn.String())
		}
	})

	repo := mustNewTelemetryTransportRepository(t, pool)
	tctx := shared.WithTenant(ctx, tenant)
	now := time.Now().UTC()
	stream := shared.ID("stream-" + id)
	agentA := shared.ID("agent-a-" + id)
	agentB := shared.ID("agent-b-" + id)

	if st, err := repo.StreamState(tctx, agentA, stream, 1); err != nil || st.Contiguous != 0 || len(st.Pending) != 0 || st.Version != 0 {
		t.Fatalf("unseen stream must be zero state: %+v err=%v", st, err)
	}

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

	gaps, err := repo.ListGaps(tctx, agentA, stream)
	if err != nil || len(gaps) != 2 || gaps[0].FromSequence != 4 || gaps[0].ToSequence != 4 || gaps[1].FromSequence != 6 || gaps[1].ToSequence != 6 {
		t.Fatalf("want materialized gaps [4,4],[6,6], got %+v err=%v", gaps, err)
	}

	stale := got
	stale.Version = 0
	stale.Contiguous, stale.Pending = 99, nil
	if err := repo.SaveStreamState(tctx, stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale-version save must conflict, got %v", err)
	}
	got.Contiguous, got.Pending = 7, nil
	if err := repo.SaveStreamState(tctx, got); err != nil {
		t.Fatal(err)
	}
	if reloaded, _ := repo.StreamState(tctx, agentA, stream, 1); reloaded.Contiguous != 7 || len(reloaded.Pending) != 0 || reloaded.Version != 2 {
		t.Fatalf("CAS did not advance state+version: %+v", reloaded)
	}
	if gaps, _ := repo.ListGaps(tctx, agentA, stream); len(gaps) != 0 {
		t.Fatalf("a fully-contiguous stream must have no open gaps, got %+v", gaps)
	}

	if err := repo.SaveStreamState(tctx, ports.TelemetryStreamState{AgentID: agentA, StreamID: stream, Epoch: 4, Contiguous: 1, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if max, _ := repo.MaxEpoch(tctx, agentA, stream); max != 4 {
		t.Fatalf("MaxEpoch = %d, want 4", max)
	}

	batch := ports.TelemetryEventBatch{
		BatchID: "batch-1", PayloadDigest: "payload-1",
		AgentID: agentA, StreamID: stream, AssetID: "as", Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, SchemaVersion: 1,
		EventTimeMin: now, EventTimeMax: now,
		ObservedCount: 5, KeptCount: 2, SampledOutCount: 1, TruncatedCount: 1, DroppedCount: 2,
		SamplingPolicyDigest: "test-policy-digest",
		Events: []ports.StoredTelemetryEvent{
			{EventID: "e1", Class: detection.ClassProcess, Digest: "d1", RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payload: []byte("p1"), ObservedAt: now},
			{EventID: "e2", Class: detection.ClassNetwork, Digest: "d2", RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payload: []byte("p2"), ObservedAt: now},
		},
	}
	if err := repo.CommitBatch(tctx, batch); err != nil {
		t.Fatalf("first batch commitment: %v", err)
	}
	if err := mustNewTelemetryTransportRepository(t, pool).CommitBatch(tctx, batch); err != nil {
		t.Fatalf("identical commitment after repository restart must be idempotent: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ports.TelemetryEventBatch)
	}{
		{"payload digest", func(b *ports.TelemetryEventBatch) { b.PayloadDigest = "different-payload" }},
		{"sampled count", func(b *ports.TelemetryEventBatch) {
			b.SampledOutCount++
			b.DroppedCount--
		}},
		{"truncated count", func(b *ports.TelemetryEventBatch) { b.TruncatedCount-- }},
		{"sampling policy digest", func(b *ports.TelemetryEventBatch) { b.SamplingPolicyDigest = "different-policy" }},
		// Widen the signed bounds instead of narrowing them, so the retained events stay
		// inside the claimed window and the repository reaches the immutable-commitment
		// comparison rather than rejecting the batch as malformed.
		{"signed minimum time", func(b *ports.TelemetryEventBatch) { b.EventTimeMin = b.EventTimeMin.Add(-time.Microsecond) }},
		{"signed maximum time", func(b *ports.TelemetryEventBatch) { b.EventTimeMax = b.EventTimeMax.Add(time.Microsecond) }},
	} {
		t.Run("commit conflict "+tc.name, func(t *testing.T) {
			conflict := batch
			tc.mutate(&conflict)
			if err := repo.CommitBatch(tctx, conflict); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("same delivery sequence with different %s must conflict, got %v", tc.name, err)
			}
		})
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
	ref := fleetagent.TelemetryReference{
		StreamID: stream, Epoch: 1, Sequence: 1, EventID: "e1", Digest: "d1",
	}
	policyDigest := strings.Repeat("a", 64)
	if status, err := repo.ResolveTelemetryReferences(tctx, agentA, "as", policyDigest, []fleetagent.TelemetryReference{ref}); err != nil || status != ports.TelemetryReferencesDurable {
		t.Fatalf("matching policy resolution = %q, %v; want durable", status, err)
	}
	if status, err := repo.ResolveTelemetryReferences(tctx, agentA, "as", strings.Repeat("b", 64), []fleetagent.TelemetryReference{ref}); err != nil || status != ports.TelemetryReferencesContradictory {
		t.Fatalf("mismatched policy resolution = %q, %v; want contradictory", status, err)
	}
	missing := ref
	missing.EventID = "missing-event"
	if status, err := repo.ResolveTelemetryReferences(tctx, agentA, "as", policyDigest, []fleetagent.TelemetryReference{missing}); err != nil || status != ports.TelemetryReferencesMissing {
		t.Fatalf("missing reference resolution = %q, %v; want missing", status, err)
	}
	if _, err := repo.ResolveTelemetryReferences(tctx, agentA, "as", "", []fleetagent.TelemetryReference{ref}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty policy digest error = %v, want validation", err)
	}

	for i, tc := range []struct {
		name       string
		slug       string
		sampledOut int
		dropped    int
	}{
		{name: "all sampled", slug: "all-sampled", sampledOut: 4},
		{name: "all dropped", slug: "all-dropped", dropped: 4},
	} {
		t.Run("zero kept "+tc.name, func(t *testing.T) {
			sequence := uint64(i + 2)
			zero := ports.TelemetryEventBatch{
				BatchID: shared.ID("zero-kept-" + tc.slug), PayloadDigest: "empty-payload-" + tc.slug,
				AgentID: agentA, StreamID: stream, AssetID: "as", Priority: fleetagent.PriorityP3,
				Epoch: 1, Sequence: sequence, SchemaVersion: 2,
				EventTimeMin: now, EventTimeMax: now.Add(time.Second),
				ObservedCount: 4, KeptCount: 0, SampledOutCount: tc.sampledOut,
				DroppedCount: tc.dropped, SamplingPolicyDigest: "zero-kept-policy",
			}
			if err := repo.CommitBatch(tctx, zero); err != nil {
				t.Fatalf("commit zero-kept batch: %v", err)
			}
			if err := mustNewTelemetryTransportRepository(t, pool).CommitBatch(tctx, zero); err != nil {
				t.Fatalf("identical zero-kept retry after repository restart: %v", err)
			}
			if n, err := repo.IngestBatchEvents(tctx, zero); err != nil || n != 0 {
				t.Fatalf("zero-kept ingest = %d, %v; want zero without a fake event", n, err)
			}
			if n, err := repo.CountBatchEvents(tctx, agentA, stream, 1, sequence); err != nil || n != 0 {
				t.Fatalf("zero-kept event count = %d, %v; want zero", n, err)
			}

			changedLane := zero
			changedLane.Priority = fleetagent.PriorityP2
			if err := repo.CommitBatch(tctx, changedLane); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("valid zero-kept lane equivocation error = %v, want conflict", err)
			}
			changedBounds := zero
			changedBounds.EventTimeMin = changedBounds.EventTimeMin.Add(-time.Microsecond)
			if err := repo.CommitBatch(tctx, changedBounds); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("valid zero-kept bounds equivocation error = %v, want conflict", err)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		mutate func(*ports.TelemetryEventBatch)
	}{
		{name: "priority lane", mutate: func(candidate *ports.TelemetryEventBatch) {
			candidate.Priority = fleetagent.PriorityP2
		}},
		{name: "event-time bounds", mutate: func(candidate *ports.TelemetryEventBatch) {
			candidate.EventTimeMin = now.Add(time.Microsecond)
			candidate.EventTimeMax = now.Add(time.Microsecond)
		}},
	} {
		t.Run("reject retained event outside "+tc.name, func(t *testing.T) {
			invalid := ports.TelemetryEventBatch{
				BatchID: "invalid-retained", PayloadDigest: "invalid-retained-payload",
				AgentID: agentA, StreamID: stream, AssetID: "as", Priority: fleetagent.PriorityP3,
				Epoch: 2, Sequence: 1, SchemaVersion: 2,
				EventTimeMin: now, EventTimeMax: now,
				ObservedCount: 1, KeptCount: 1, SamplingPolicyDigest: "invalid-retained-policy",
				Events: []ports.StoredTelemetryEvent{{
					EventID: "invalid-event", Class: detection.ClassProcess, Digest: "invalid-digest",
					RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Payload:               []byte("payload"), ObservedAt: now,
				}},
			}
			tc.mutate(&invalid)
			if err := repo.CommitBatch(tctx, invalid); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("CommitBatch() error = %v, want validation", err)
			}
		})
	}

	if st, _ := repo.StreamState(tctx, agentB, stream, 1); st.Contiguous != 0 || st.Version != 0 {
		t.Fatalf("sibling agent must see zero state for the same stream id, got %+v", st)
	}
	if max, _ := repo.MaxEpoch(tctx, agentB, stream); max != 0 {
		t.Fatalf("sibling agent MaxEpoch must be 0, got %d", max)
	}
	if n, _ := repo.CountBatchEvents(tctx, agentB, stream, 1, 1); n != 0 {
		t.Fatalf("sibling agent must not see agentA's events, got %d", n)
	}

	octx := shared.WithTenant(ctx, other)
	if err := repo.CommitBatch(octx, batch); err != nil {
		t.Fatalf("same coordinate in another tenant must be independent: %v", err)
	}
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
