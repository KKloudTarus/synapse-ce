package memory

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTelemetryBatchCommitPreservesSignedAccounting(t *testing.T) {
	store := NewTelemetryTransportStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 123_456_789, time.UTC)
	batch := ports.TelemetryEventBatch{
		BatchID: "batch-1", PayloadDigest: "payload-1",
		AgentID: "agent-1", StreamID: "stream-1", AssetID: "asset-1",
		Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, SchemaVersion: 2,
		EventTimeMin: at, EventTimeMax: at.Add(time.Second),
		ObservedCount: 5, KeptCount: 2, SampledOutCount: 1,
		TruncatedCount: 1, DroppedCount: 2,
		SamplingPolicyDigest: "policy-digest-1",
		Events: []ports.StoredTelemetryEvent{
			{EventID: "event-1", Class: detection.ClassProcess, Digest: "digest-1", RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payload: []byte("one"), ObservedAt: at},
			{EventID: "event-2", Class: detection.ClassProcess, Digest: "digest-2", RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payload: []byte("two"), ObservedAt: at.Add(time.Second)},
		},
	}
	if err := store.CommitBatch(ctx, batch); err != nil {
		t.Fatalf("commit batch: %v", err)
	}
	if err := store.CommitBatch(ctx, batch); err != nil {
		t.Fatalf("identical retry: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*ports.TelemetryEventBatch)
	}{
		{"sampled disposition", func(b *ports.TelemetryEventBatch) {
			b.SampledOutCount++
			b.DroppedCount--
		}},
		{"truncation quality", func(b *ports.TelemetryEventBatch) { b.TruncatedCount-- }},
		{"sampling policy", func(b *ports.TelemetryEventBatch) { b.SamplingPolicyDigest = "policy-digest-2" }},
		// Widen the signed bounds rather than narrowing them: the retained events must stay
		// inside the claimed window so the store reaches the immutable-commitment comparison
		// instead of rejecting the batch as malformed.
		{"signed minimum time", func(b *ports.TelemetryEventBatch) { b.EventTimeMin = b.EventTimeMin.Add(-time.Microsecond) }},
		{"signed maximum time", func(b *ports.TelemetryEventBatch) { b.EventTimeMax = b.EventTimeMax.Add(time.Microsecond) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conflict := batch
			tc.mutate(&conflict)
			if err := store.CommitBatch(ctx, conflict); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("different immutable accounting error = %v, want conflict", err)
			}
		})
	}

	if err := store.CommitBatch(shared.WithTenant(t.Context(), "tenant-b"), batch); err != nil {
		t.Fatalf("same commitment in another tenant: %v", err)
	}
}

func TestTelemetryReferenceResolutionBindsRedactionPolicyDigest(t *testing.T) {
	store := NewTelemetryTransportStore()
	ctx := shared.WithTenant(t.Context(), "tenant-reference-policy")
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	policyDigest := strings.Repeat("a", 64)
	batch := ports.TelemetryEventBatch{
		BatchID: "batch-reference-policy", PayloadDigest: "payload-reference-policy",
		AgentID: "agent-1", StreamID: "stream-1", AssetID: "asset-1",
		Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, SchemaVersion: 2,
		EventTimeMin: at, EventTimeMax: at,
		ObservedCount: 1, KeptCount: 1, SamplingPolicyDigest: "sampling-policy",
		Events: []ports.StoredTelemetryEvent{{
			EventID: "event-1", Class: detection.ClassProcess, Digest: strings.Repeat("b", 64),
			RedactionPolicyDigest: policyDigest, Payload: []byte("payload"), ObservedAt: at,
		}},
	}
	if err := store.CommitBatch(ctx, batch); err != nil {
		t.Fatalf("commit batch: %v", err)
	}
	if n, err := store.IngestBatchEvents(ctx, batch); err != nil || n != 1 {
		t.Fatalf("ingest events = %d, %v; want 1", n, err)
	}
	ref := fleetagent.TelemetryReference{
		StreamID: batch.StreamID, Epoch: batch.Epoch, Sequence: batch.Sequence,
		EventID: batch.Events[0].EventID, Digest: batch.Events[0].Digest,
	}

	status, err := store.ResolveTelemetryReferences(ctx, batch.AgentID, batch.AssetID, policyDigest, []fleetagent.TelemetryReference{ref})
	if err != nil || status != ports.TelemetryReferencesDurable {
		t.Fatalf("matching policy resolution = %q, %v; want durable", status, err)
	}
	status, err = store.ResolveTelemetryReferences(ctx, batch.AgentID, batch.AssetID, strings.Repeat("c", 64), []fleetagent.TelemetryReference{ref})
	if err != nil || status != ports.TelemetryReferencesContradictory {
		t.Fatalf("mismatched policy resolution = %q, %v; want contradictory", status, err)
	}
	missing := ref
	missing.EventID = "missing-event"
	status, err = store.ResolveTelemetryReferences(ctx, batch.AgentID, batch.AssetID, policyDigest, []fleetagent.TelemetryReference{missing})
	if err != nil || status != ports.TelemetryReferencesMissing {
		t.Fatalf("missing reference resolution = %q, %v; want missing", status, err)
	}
	if _, err := store.ResolveTelemetryReferences(ctx, batch.AgentID, batch.AssetID, "", []fleetagent.TelemetryReference{ref}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty policy digest error = %v, want validation", err)
	}
}

func TestTelemetryBatchCommitSupportsZeroKeptAccounting(t *testing.T) {
	for _, tc := range []struct {
		name       string
		priority   fleetagent.DeliveryPriority
		sampledOut int
		dropped    int
	}{
		{name: "all sampled", priority: fleetagent.PriorityP3, sampledOut: 4},
		{name: "all dropped", priority: fleetagent.PriorityP3, dropped: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewTelemetryTransportStore()
			ctx := shared.WithTenant(t.Context(), "tenant-zero-kept")
			at := time.Date(2026, 8, 27, 13, 0, 0, 0, time.UTC)
			batch := ports.TelemetryEventBatch{
				BatchID: "zero-kept", PayloadDigest: "empty-payload",
				AgentID: "agent-1", StreamID: "stream-1", AssetID: "asset-1",
				Priority: tc.priority, Epoch: 1, Sequence: 1, SchemaVersion: 2,
				EventTimeMin: at, EventTimeMax: at.Add(time.Second),
				ObservedCount: 4, KeptCount: 0, SampledOutCount: tc.sampledOut,
				DroppedCount: tc.dropped, SamplingPolicyDigest: "policy-digest-1",
			}
			if err := store.CommitBatch(ctx, batch); err != nil {
				t.Fatalf("commit zero-kept batch: %v", err)
			}
			if err := store.CommitBatch(ctx, batch); err != nil {
				t.Fatalf("identical zero-kept retry: %v", err)
			}
			if n, err := store.IngestBatchEvents(ctx, batch); err != nil || n != 0 {
				t.Fatalf("zero-kept ingest = %d, %v; want zero without a fake event", n, err)
			}

			changedLane := batch
			changedLane.Priority = fleetagent.PriorityP2
			if err := store.CommitBatch(ctx, changedLane); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("valid zero-kept lane equivocation error = %v, want conflict", err)
			}
		})
	}
}

func TestTelemetryBatchCommitRejectsRetainedEventsOutsideSignedClaims(t *testing.T) {
	at := time.Date(2026, 8, 27, 14, 0, 0, 0, time.UTC)
	base := ports.TelemetryEventBatch{
		BatchID: "batch-invalid", PayloadDigest: "payload-invalid",
		AgentID: "agent-1", StreamID: "stream-1", AssetID: "asset-1",
		Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, SchemaVersion: 2,
		EventTimeMin: at, EventTimeMax: at, ObservedCount: 1, KeptCount: 1,
		SamplingPolicyDigest: "policy-digest-1",
		Events: []ports.StoredTelemetryEvent{{
			EventID: "event-1", Class: detection.ClassProcess, Digest: "digest-1",
			RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Payload:               []byte("one"), ObservedAt: at,
		}},
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ports.TelemetryEventBatch)
	}{
		{name: "priority lane", mutate: func(batch *ports.TelemetryEventBatch) { batch.Priority = fleetagent.PriorityP2 }},
		{name: "event-time bounds", mutate: func(batch *ports.TelemetryEventBatch) {
			batch.EventTimeMin = at.Add(time.Microsecond)
			batch.EventTimeMax = at.Add(time.Microsecond)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch := base
			tc.mutate(&batch)
			store := NewTelemetryTransportStore()
			if err := store.CommitBatch(shared.WithTenant(t.Context(), "tenant-invalid"), batch); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("CommitBatch() error = %v, want validation", err)
			}
		})
	}
}

func TestTelemetryBatchAccountingQueryUsesHalfOpenOverlapAndTenantScope(t *testing.T) {
	store := NewTelemetryTransportStore()
	tenantA := shared.WithTenant(t.Context(), "tenant-a")
	tenantB := shared.WithTenant(t.Context(), "tenant-b")
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	batchAt := func(id shared.ID, sequence uint64, at time.Time) ports.TelemetryEventBatch {
		return ports.TelemetryEventBatch{
			BatchID: id, PayloadDigest: "payload-" + id.String(),
			AgentID: "agent-1", StreamID: "stream-1", AssetID: "asset-1",
			Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: sequence, SchemaVersion: 1,
			EventTimeMin: at, EventTimeMax: at,
			ObservedCount: 1, KeptCount: 1, SamplingPolicyDigest: "policy-1",
			Events: []ports.StoredTelemetryEvent{{
				EventID: shared.ID("event-" + id.String()), Class: detection.ClassProcess,
				Digest: "digest-" + id.String(), RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payload: []byte("payload"), ObservedAt: at,
			}},
		}
	}
	for _, batch := range []ports.TelemetryEventBatch{
		batchAt("before", 1, since.Add(-time.Nanosecond)),
		batchAt("at-since", 2, since),
		batchAt("inside", 3, since.Add(time.Minute)),
		batchAt("at-until", 4, since.Add(2*time.Minute)),
	} {
		if err := store.CommitBatch(tenantA, batch); err != nil {
			t.Fatalf("commit %s: %v", batch.BatchID, err)
		}
	}
	if err := store.CommitBatch(tenantB, batchAt("other-tenant", 1, since.Add(time.Minute))); err != nil {
		t.Fatalf("commit other tenant: %v", err)
	}

	query := ports.TelemetryBatchAccountingQuery{
		AgentID: "agent-1", AssetID: "asset-1", Since: since, Until: since.Add(2 * time.Minute),
	}
	rows, err := store.QueryTelemetryBatchAccounting(tenantA, query)
	if err != nil {
		t.Fatalf("query accounting: %v", err)
	}
	want := []shared.ID{"at-since", "inside"}
	if len(rows) != len(want) {
		t.Fatalf("accounting count = %d, want %d: %#v", len(rows), len(want), rows)
	}
	for i := range want {
		if rows[i].BatchID != want[i] {
			t.Fatalf("batch[%d] = %q, want %q", i, rows[i].BatchID, want[i])
		}
	}
	other, err := store.QueryTelemetryBatchAccounting(tenantB, query)
	if err != nil {
		t.Fatalf("query other tenant: %v", err)
	}
	if len(other) != 1 || other[0].BatchID != "other-tenant" {
		t.Fatalf("other tenant accounting = %#v", other)
	}
}
