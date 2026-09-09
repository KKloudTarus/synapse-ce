package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestCorrelationStateStoreCASAndTenantIsolation(t *testing.T) {
	store := NewCorrelationStateStore()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	at := time.Unix(1_800_000_000, 0).UTC()
	next := correlation.Checkpoint{Revision: 1, MaxObservedAt: at, Watermark: at.Add(-time.Minute)}
	added := []correlation.Assignment{{SignalID: "det-1", IncidentID: "inc-1", AssetID: "asset-1", OccurredAt: at, Severity: shared.SeverityHigh, Outcome: correlation.AssignmentAttached}}
	if err := store.advanceCorrelationState(ctx, "eng-1", 0, next, added, []correlation.ActiveSession{{AssetID: "asset-1", IncidentID: "inc-1", MinOccurredAt: at, MaxOccurredAt: at, ReflectedCount: 1, MaxSeverity: shared.SeverityHigh}}); err != nil {
		t.Fatal(err)
	}
	if err := store.advanceCorrelationState(ctx, "eng-1", 0, next, added, []correlation.ActiveSession{{AssetID: "asset-1", IncidentID: "inc-1", MinOccurredAt: at, MaxOccurredAt: at, ReflectedCount: 1, MaxSeverity: shared.SeverityHigh}}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale revision must conflict, got %v", err)
	}
	backward := correlation.Checkpoint{Revision: 2, MaxObservedAt: at.Add(-time.Second), Watermark: at.Add(-2 * time.Minute)}
	if err := store.advanceCorrelationState(ctx, "eng-1", 1, backward, nil, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("backward checkpoint must be rejected, got %v", err)
	}
	got, err := store.LoadCorrelationState(ctx, "eng-1", []shared.ID{"det-1"}, 100)
	if err != nil || got.Checkpoint != next || len(got.ActiveSessions) != 1 || len(got.KnownSignalIDs) != 1 {
		t.Fatalf("stored state mismatch: %+v err=%v", got, err)
	}
	got.ActiveSessions[0].IncidentID = "mutated"
	again, _ := store.LoadCorrelationState(ctx, "eng-1", []shared.ID{"det-1"}, 100)
	if again.ActiveSessions[0].IncidentID != "inc-1" {
		t.Fatal("returned active sessions must not alias stored state")
	}
	other, err := store.LoadCorrelationState(shared.WithTenant(context.Background(), "tenant-b"), "eng-1", []shared.ID{"det-1"}, 100)
	if err != nil || other.Checkpoint.Revision != 0 || len(other.ActiveSessions) != 0 || len(other.KnownSignalIDs) != 0 {
		t.Fatalf("cross-tenant state leaked: %+v err=%v", other, err)
	}
}

func TestCorrelationStateStoreStagesIdempotentlyAndRejectsInvalidConsumeBeforeMutation(t *testing.T) {
	store := NewCorrelationStateStore()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	at := time.Unix(1_800_000_000, 0).UTC()
	snapshot := correlation.SourcePosition{RecordedAt: at, ID: "snapshot-1"}
	started, err := store.BeginCorrelationSnapshot(ctx, "eng-1", 0, snapshot, at, "policy")
	if err != nil {
		t.Fatal(err)
	}
	next := started
	next.Revision++
	next.Phase = correlation.PhaseConsume
	next.SourceCursor = snapshot
	signal := correlation.Signal{ID: "signal-1", AssetID: "asset-1", OccurredAt: at, Severity: shared.SeverityHigh}
	if err := store.StageCorrelationSignals(ctx, "eng-1", started.Revision, next, []correlation.Signal{signal}); err != nil {
		t.Fatal(err)
	}
	if err := store.StageCorrelationSignals(ctx, "eng-1", started.Revision, next, []correlation.Signal{signal}); err != nil {
		t.Fatalf("exact stage retry: %v", err)
	}
	conflicting := signal
	conflicting.Title = "equivocated"
	if err := store.StageCorrelationSignals(ctx, "eng-1", started.Revision, next, []correlation.Signal{conflicting}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("conflicting stage retry error=%v", err)
	}
	additional := signal
	additional.ID = "signal-2"
	if err := store.StageCorrelationSignals(ctx, "eng-1", started.Revision, next, []correlation.Signal{additional}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("additional stage retry error=%v", err)
	}
	before, err := store.LoadCorrelationState(ctx, "eng-1", nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	sourceStarted, err := store.BeginCorrelationSnapshot(ctx, "eng-source", 0, snapshot, at, "policy")
	if err != nil {
		t.Fatal(err)
	}
	sourceAdvanced := sourceStarted
	sourceAdvanced.Revision++
	sourceAdvanced.SourceCursor = snapshot
	if err := store.StageCorrelationSignals(ctx, "eng-source", sourceStarted.Revision, sourceAdvanced, nil); err != nil {
		t.Fatal(err)
	}
	invalidSource := sourceAdvanced
	invalidSource.Revision++
	invalidSource.Phase = correlation.PhaseConsume
	invalidSource.SourceCursor = correlation.SourcePosition{}
	if err := store.StageCorrelationSignals(ctx, "eng-source", sourceAdvanced.Revision, invalidSource, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("regressing source cursor error=%v", err)
	}
	afterSource, err := store.LoadCorrelationState(ctx, "eng-source", nil, 100)
	if err != nil || afterSource.Checkpoint != sourceAdvanced {
		t.Fatalf("invalid source transition mutated state=%+v before=%+v err=%v", afterSource.Checkpoint, sourceAdvanced, err)
	}
	invalid := next
	invalid.Revision++
	invalid.StagedCursor.ID = "without-time"
	if err := store.CommitCorrelationConsume(ctx, "eng-1", next.Revision, invalid, nil, nil, snapshot, false); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("malformed consume error=%v", err)
	}
	after, err := store.LoadCorrelationState(ctx, "eng-1", nil, 100)
	if err != nil || after.Checkpoint != before.Checkpoint {
		t.Fatalf("invalid consume mutated state=%+v before=%+v err=%v", after.Checkpoint, before.Checkpoint, err)
	}
	final := next
	final.Revision++
	final.Phase = ""
	if err := store.CommitCorrelationConsume(ctx, "eng-1", next.Revision, final, nil, nil, snapshot, true); err != nil {
		t.Fatal(err)
	}
	finished, err := store.LoadCorrelationState(ctx, "eng-1", nil, 100)
	if err != nil || finished.Checkpoint.Completed != snapshot || finished.Checkpoint.Phase != "" || !finished.Checkpoint.Snapshot.RecordedAt.IsZero() || finished.Checkpoint.PolicyDigest != "" {
		t.Fatalf("finalized state=%+v err=%v", finished.Checkpoint, err)
	}
	staged, more, err := store.ListStagedCorrelationSignals(ctx, "eng-1", snapshot, correlation.SignalPosition{}, 10)
	if err != nil || more || len(staged) != 0 {
		t.Fatalf("final consume must prune exact staged snapshot: staged=%v more=%v err=%v", staged, more, err)
	}
}

func TestCorrelationStateStoreIntermediateRetainsFinalizedWatermarkAndFinalPrunes(t *testing.T) {
	store := NewCorrelationStateStore()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	at := time.Unix(1_800_000_000, 0).UTC()
	snapshot := correlation.SourcePosition{RecordedAt: at, ID: "snapshot-1"}
	started, err := store.BeginCorrelationSnapshot(ctx, "eng-1", 0, snapshot, at, "policy")
	if err != nil {
		t.Fatal(err)
	}
	staged := started
	staged.Revision++
	staged.Phase, staged.SourceCursor = correlation.PhaseConsume, snapshot
	signal := correlation.Signal{ID: "signal-1", AssetID: "asset-1", OccurredAt: at, Severity: shared.SeverityHigh}
	if err := store.StageCorrelationSignals(ctx, "eng-1", started.Revision, staged, []correlation.Signal{signal}); err != nil {
		t.Fatal(err)
	}
	intermediate := staged
	intermediate.Revision++
	intermediate.StagedCursor = correlation.SignalPosition{OccurredAt: at, ID: signal.ID}
	intermediate.MaxObservedAt, intermediate.Watermark = at.Add(time.Minute), at
	active := correlation.ActiveSession{AssetID: "asset-1", IncidentID: "inc-1", MinOccurredAt: at, MaxOccurredAt: at, ReflectedCount: 1, MaxSeverity: shared.SeverityHigh}
	if err := store.CommitCorrelationConsume(ctx, "eng-1", staged.Revision, intermediate, nil, []correlation.ActiveSession{active}, snapshot, false); err != nil {
		t.Fatal(err)
	}
	mid, err := store.LoadCorrelationState(ctx, "eng-1", nil, 10)
	if err != nil || mid.Checkpoint.Watermark != at || len(mid.ActiveSessions) != 1 {
		t.Fatalf("intermediate state=%+v err=%v", mid, err)
	}
	stagedRows, more, err := store.ListStagedCorrelationSignals(ctx, "eng-1", snapshot, correlation.SignalPosition{}, 10)
	if err != nil || more || len(stagedRows) != 1 {
		t.Fatalf("intermediate must retain staged data=%v more=%v err=%v", stagedRows, more, err)
	}
	final := intermediate
	final.Revision++
	final.Phase = ""
	if err := store.CommitCorrelationConsume(ctx, "eng-1", intermediate.Revision, final, nil, nil, snapshot, true); err != nil {
		t.Fatal(err)
	}
	finished, err := store.LoadCorrelationState(ctx, "eng-1", nil, 10)
	if err != nil || finished.Checkpoint.Completed != snapshot || finished.Checkpoint.Watermark != at || len(finished.ActiveSessions) != 0 {
		t.Fatalf("final state=%+v err=%v", finished, err)
	}
	stagedRows, more, err = store.ListStagedCorrelationSignals(ctx, "eng-1", snapshot, correlation.SignalPosition{}, 10)
	if err != nil || more || len(stagedRows) != 0 {
		t.Fatalf("final must prune staged data=%v more=%v err=%v", stagedRows, more, err)
	}
}

func TestCorrelationStateStoreKeepsLedgerAfterActiveSessionReplacement(t *testing.T) {
	store := NewCorrelationStateStore()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	at := time.Unix(1_800_000_000, 0).UTC()
	assignment := correlation.Assignment{SignalID: "historical", IncidentID: "inc-1", AssetID: "asset-1", OccurredAt: at, Outcome: correlation.AssignmentTooLate}
	next := correlation.Checkpoint{Revision: 1, MaxObservedAt: at, Watermark: at}
	if err := store.advanceCorrelationState(ctx, "eng-1", 0, next, []correlation.Assignment{assignment}, nil); err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadCorrelationState(ctx, "eng-1", []shared.ID{"historical"}, 100)
	if err != nil || len(state.KnownSignalIDs) != 1 || len(state.ActiveSessions) != 0 {
		t.Fatalf("ledger lookup=%+v err=%v", state, err)
	}
}
