package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func outboxIntent(id string, at time.Time) ports.FleetAuditIntent {
	return ports.FleetAuditIntent{
		ID: id,
		Entry: ports.AuditEntry{
			Actor: "agent-1", Action: "fleet.telemetry.batch_commit", Target: "stream-1", At: at,
			Metadata: map[string]string{"idempotency_key": id, "batch_id": "batch-1"},
		},
	}
}

func outboxBatch(at time.Time) ports.TelemetryEventBatch {
	return ports.TelemetryEventBatch{
		BatchID: "batch-1", PayloadDigest: "payload-1",
		AgentID: "agent-1", StreamID: "stream-1", AssetID: "asset-1",
		Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, SchemaVersion: 2,
		EventTimeMin: at, EventTimeMax: at.Add(time.Second),
		ObservedCount: 1, KeptCount: 1, SamplingPolicyDigest: "policy-digest-1",
		Events: []ports.StoredTelemetryEvent{{
			EventID: "event-1", Class: detection.ClassProcess, Digest: "digest-1",
			RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Payload:               []byte("one"), ObservedAt: at,
		}},
	}
}

// The batch commitment and its audit obligation share one critical section: after a
// successful commit the obligation is durable and pending, and the returned payload
// is the one the caller must audit.
func TestCommitBatchWithAuditCommitsObligationWithState(t *testing.T) {
	store := NewTelemetryTransportStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	intent := outboxIntent("fleet.telemetry.batch_commit:one", at)

	committed, err := store.CommitBatchWithAudit(ctx, outboxBatch(at), intent)
	if err != nil {
		t.Fatalf("commit batch with audit: %v", err)
	}
	if committed.ID != intent.ID || !committed.Entry.At.Equal(intent.Entry.At) {
		t.Fatalf("committed intention=%#v, want the admitted payload", committed.Entry)
	}
	pending, err := store.ListPendingFleetAudits(ctx)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != intent.ID {
		t.Fatalf("pending=%#v, want exactly %s", pending, intent.ID)
	}
	if err := store.AcknowledgeFleetAudit(ctx, intent.ID); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	pending, err = store.ListPendingFleetAudits(ctx)
	if err != nil {
		t.Fatalf("list pending after acknowledgement: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("acknowledged obligation still pending: %#v", pending)
	}
}

// An exact batch retry must re-deliver the ORIGINAL audit payload. A retry arriving
// an hour later carries a later wall clock, and if that leaked through, the second
// delivery would hash a different entry for one intention identity.
func TestCommitBatchWithAuditRetryReturnsOriginalPayload(t *testing.T) {
	store := NewTelemetryTransportStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	batch := outboxBatch(at)

	first, err := store.CommitBatchWithAudit(ctx, batch, outboxIntent("batch-intent", at))
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}
	retry, err := store.CommitBatchWithAudit(ctx, batch, outboxIntent("batch-intent", at.Add(time.Hour)))
	if err != nil {
		t.Fatalf("exact retry must be idempotent, got %v", err)
	}
	if !retry.Entry.At.Equal(first.Entry.At) {
		t.Fatalf("retry at=%v, want the original %v", retry.Entry.At, first.Entry.At)
	}
	pending, err := store.ListPendingFleetAudits(ctx)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending obligations=%d, want 1", len(pending))
	}
}

// Reusing one intention identity for genuinely different audit content is an
// equivocation: the mutation must be refused rather than recorded under a
// misleading obligation.
func TestCommitBatchWithAuditRejectsIntentionEquivocation(t *testing.T) {
	store := NewTelemetryTransportStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	batch := outboxBatch(at)
	if _, err := store.CommitBatchWithAudit(ctx, batch, outboxIntent("batch-intent", at)); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	conflicting := outboxIntent("batch-intent", at)
	conflicting.Entry.Actor = "another-agent"
	if _, err := store.CommitBatchWithAudit(ctx, batch, conflicting); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want conflict for a re-used intention identity, got %v", err)
	}
}

// State and obligation share one fate: a malformed intention must leave no batch
// commitment behind, or committed identity would exist with no audit obligation.
func TestCommitBatchWithAuditLeavesNoStateOnRejectedIntention(t *testing.T) {
	store := NewTelemetryTransportStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	batch := outboxBatch(at)

	broken := outboxIntent("batch-intent", at)
	broken.Entry.Metadata["idempotency_key"] = "a-different-key"
	if _, err := store.CommitBatchWithAudit(ctx, batch, broken); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error, got %v", err)
	}
	pending, err := store.ListPendingFleetAudits(ctx)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("rejected intention became pending: %#v", pending)
	}
	// The commitment must not have been claimed, so a later batch may still take this
	// coordinate with different content without hitting an equivocation conflict.
	other := batch
	other.BatchID = "batch-2"
	other.PayloadDigest = "payload-2"
	if err := store.CommitBatch(ctx, other); err != nil {
		t.Fatalf("coordinate was claimed despite the rejected intention: %v", err)
	}
}

// A pending obligation belongs to exactly one tenant's recovery sweep.
func TestFleetAuditOutboxIsolatesTenants(t *testing.T) {
	store := NewTelemetryTransportStore()
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	ctxA := shared.WithTenant(t.Context(), "tenant-a")
	ctxB := shared.WithTenant(t.Context(), "tenant-b")
	if _, err := store.CommitBatchWithAudit(ctxA, outboxBatch(at), outboxIntent("batch-intent", at)); err != nil {
		t.Fatalf("commit for tenant a: %v", err)
	}
	pending, err := store.ListPendingFleetAudits(ctxB)
	if err != nil {
		t.Fatalf("list pending for tenant b: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("tenant b sees tenant a obligations: %#v", pending)
	}
	if err := store.AcknowledgeFleetAudit(ctxB, "batch-intent"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant acknowledge=%v, want not-found", err)
	}
	own, err := store.ListPendingFleetAudits(ctxA)
	if err != nil || len(own) != 1 {
		t.Fatalf("tenant a pending=%#v/%v, want exactly one", own, err)
	}
}

// Tenant ids and intention ids both contain colons, so a concatenated
// "tenant:id" key is ambiguous: tenant "a" with intention "b:x" and tenant "a:b"
// with intention "x" would land on one key. That let a prefix scan list — and an
// acknowledgement retire — another tenant's audit obligation.
func TestFleetAuditOutboxKeysAreUnambiguousAcrossTenantBoundary(t *testing.T) {
	store := NewTelemetryTransportStore()
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	ctxShort := shared.WithTenant(t.Context(), "a")
	ctxLong := shared.WithTenant(t.Context(), "a:b")

	if _, err := store.CommitBatchWithAudit(ctxShort, outboxBatch(at), outboxIntent("b:x", at)); err != nil {
		t.Fatalf("commit for tenant a: %v", err)
	}
	if _, err := store.CommitBatchWithAudit(ctxLong, outboxBatch(at), outboxIntent("x", at)); err != nil {
		t.Fatalf("commit for tenant a:b: %v", err)
	}
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		wantID string
	}{
		{"tenant a", ctxShort, "b:x"},
		{"tenant a:b", ctxLong, "x"},
	} {
		pending, err := store.ListPendingFleetAudits(tc.ctx)
		if err != nil {
			t.Fatalf("%s list pending: %v", tc.name, err)
		}
		if len(pending) != 1 || pending[0].ID != tc.wantID {
			t.Fatalf("%s pending=%#v, want exactly %q", tc.name, pending, tc.wantID)
		}
	}
	// Acknowledging under the wrong tenant must not retire the colliding obligation.
	if err := store.AcknowledgeFleetAudit(ctxShort, "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-boundary acknowledge=%v, want not-found", err)
	}
	pending, err := store.ListPendingFleetAudits(ctxLong)
	if err != nil {
		t.Fatalf("list pending for tenant a:b: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("tenant a:b obligation was retired by another tenant: %#v", pending)
	}
}

func TestFleetAuditOutboxAcknowledgementValidation(t *testing.T) {
	store := NewTelemetryTransportStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	if err := store.AcknowledgeFleetAudit(ctx, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error for an empty id, got %v", err)
	}
	if err := store.AcknowledgeFleetAudit(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not-found for an unknown id, got %v", err)
	}
	if _, err := store.ListPendingFleetAudits(t.Context()); err == nil {
		t.Fatal("listing obligations without a tenant must fail")
	}
}
