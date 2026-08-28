package memory

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func provenanceAdmission(tenant, engagement, detection shared.ID, at time.Time) (detectionprovenance.Current, detectionprovenance.Transition) {
	current := detectionprovenance.Current{
		TenantID: tenant, EngagementID: engagement, DetectionID: detection, Status: detectionprovenance.StatusPending,
		PendingInput: []byte("durable input for " + string(detection)), UpdatedAt: at,
	}
	received := detectionprovenance.Transition{
		TenantID: tenant, EngagementID: engagement, DetectionID: detection, Sequence: 1,
		Kind: detectionprovenance.Received, Status: detectionprovenance.StatusPending,
		TelemetryRefs: []fleetagent.TelemetryReference{{StreamID: "stream-1", Epoch: 1, Sequence: 1, EventID: "event-1", Digest: "digest-1"}},
		AgentID:       "agent-1", AssetID: "asset-1", OccurredAt: at,
	}
	return current, received
}

func provenanceTransition(current detectionprovenance.Current, kind detectionprovenance.TransitionKind, status detectionprovenance.Status, at time.Time) detectionprovenance.Transition {
	return detectionprovenance.Transition{
		TenantID: current.TenantID, EngagementID: current.EngagementID, DetectionID: current.DetectionID, Sequence: 2,
		Kind: kind, Status: status, OccurredAt: at,
	}
}

func requireProvenanceCurrent(t *testing.T, store *DetectionProvenanceStore, ctx context.Context, want detectionprovenance.Current) {
	t.Helper()
	got, found, err := store.Current(ctx, want.EngagementID, want.DetectionID)
	if err != nil {
		t.Fatalf("get current: %v", err)
	}
	if !found || !reflect.DeepEqual(got, want) {
		t.Fatalf("current = %#v, found=%t; want %#v", got, found, want)
	}
}

func TestDetectionProvenanceLifecycleRejectsSkippedAndInvalidTransitions(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	current, received := provenanceAdmission("tenant-a", "eng-1", "detection-1", at)
	if err := store.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit pending: %v", err)
	}

	tests := []struct {
		name       string
		kind       detectionprovenance.TransitionKind
		status     detectionprovenance.Status
		evidenceID shared.ID
		want       error
	}{
		{name: "skip to commitment pending", kind: detectionprovenance.CommitmentPending, status: detectionprovenance.StatusPending, want: shared.ErrConflict},
		{name: "skip to sealed", kind: detectionprovenance.CommitmentSealed, status: detectionprovenance.StatusPending, evidenceID: "evidence-1", want: shared.ErrConflict},
		{name: "acknowledge before seal", kind: detectionprovenance.Acknowledged, status: detectionprovenance.StatusComplete, evidenceID: "evidence-1", want: shared.ErrConflict},
		{name: "durable marked complete", kind: detectionprovenance.TelemetryDurable, status: detectionprovenance.StatusComplete, want: shared.ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transition := provenanceTransition(current, tt.kind, tt.status, at.Add(time.Minute))
			transition.EvidenceID = tt.evidenceID
			if err := store.AppendTransition(ctx, transition); !errors.Is(err, tt.want) {
				t.Fatalf("append transition error = %v, want %v", err, tt.want)
			}
		})
	}
	history, err := store.ListTransitions(ctx, current.EngagementID, current.DetectionID)
	if err != nil || len(history) != 1 {
		t.Fatalf("history after rejected transitions = %#v, err=%v; want received only", history, err)
	}
}

func TestDetectionProvenanceLifecycleEnforcesEvidenceIdentityAndTerminalStates(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	current, received := provenanceAdmission("tenant-a", "eng-1", "detection-1", at)
	if err := store.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit pending: %v", err)
	}
	for i, kind := range []detectionprovenance.TransitionKind{detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending} {
		if err := store.AppendTransition(ctx, provenanceTransition(current, kind, detectionprovenance.StatusPending, at.Add(time.Duration(i+1)*time.Minute))); err != nil {
			t.Fatalf("append %s: %v", kind, err)
		}
	}
	sealed := provenanceTransition(current, detectionprovenance.CommitmentSealed, detectionprovenance.StatusPending, at.Add(3*time.Minute))
	sealed.EvidenceID = "evidence-1"
	if err := store.AppendTransition(ctx, sealed); err != nil {
		t.Fatalf("append sealed: %v", err)
	}
	wrongACK := provenanceTransition(current, detectionprovenance.Acknowledged, detectionprovenance.StatusComplete, at.Add(4*time.Minute))
	wrongACK.EvidenceID = "evidence-2"
	if err := store.AppendTransition(ctx, wrongACK); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed evidence ACK error = %v, want conflict", err)
	}
	ack := wrongACK
	ack.EvidenceID = "evidence-1"
	if err := store.AppendTransition(ctx, ack); err != nil {
		t.Fatalf("append acknowledged: %v", err)
	}
	contradictory := provenanceTransition(current, detectionprovenance.TelemetryDurable, detectionprovenance.StatusPending, at.Add(5*time.Minute))
	contradictory.AgentID = "unexpected-agent"
	if err := store.AppendTransition(ctx, contradictory); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("advance complete lifecycle error = %v, want conflict", err)
	}
	expired := provenanceTransition(current, detectionprovenance.Expired, detectionprovenance.StatusExpired, at.Add(5*time.Minute))
	expired.EvidenceID = "evidence-1"
	if err := store.AppendTransition(ctx, expired); err != nil {
		t.Fatalf("expire complete provenance: %v", err)
	}
	if err := store.AppendTransition(ctx, provenanceTransition(current, detectionprovenance.Broken, detectionprovenance.StatusBroken, at.Add(6*time.Minute))); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("broken without reason error = %v, want validation", err)
	}
	broken := provenanceTransition(current, detectionprovenance.Broken, detectionprovenance.StatusBroken, at.Add(6*time.Minute))
	broken.Reason = "later integrity failure"
	broken.EvidenceID = "evidence-1"
	if err := store.AppendTransition(ctx, broken); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("advance expired lifecycle error = %v, want conflict", err)
	}
}

func TestDetectionProvenanceStoreConcurrentIdenticalAdmissionIsIdempotent(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	current, received := provenanceAdmission("tenant-a", "eng-1", "detection-1", time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC))

	const callers = 16
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			errs <- store.AdmitPending(ctx, current, received)
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent identical admission: %v", err)
		}
	}

	history, err := store.ListTransitions(ctx, current.EngagementID, current.DetectionID)
	if err != nil {
		t.Fatalf("list admission history: %v", err)
	}
	if len(history) != 1 || history[0].Kind != detectionprovenance.Received || history[0].Sequence != 1 {
		t.Fatalf("admission history = %#v, want one received transition", history)
	}
}

func TestDetectionProvenanceStoreRetriesAdmissionAtLaterTime(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 123_456_789, time.UTC)
	current, received := provenanceAdmission("tenant-a", "eng-1", "detection-1", at)
	if err := store.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit pending: %v", err)
	}
	retryCurrent := current
	retryCurrent.UpdatedAt = at.Add(time.Hour)
	retryReceived := received
	retryReceived.OccurredAt = at.Add(time.Hour)
	if err := store.AdmitPending(ctx, retryCurrent, retryReceived); err != nil {
		t.Fatalf("later admission retry: %v", err)
	}
	got, found, err := store.Current(ctx, current.EngagementID, current.DetectionID)
	if err != nil || !found || !got.UpdatedAt.Equal(current.UpdatedAt) {
		t.Fatalf("current after retry = %#v, found=%t, err=%v; want first timestamp", got, found, err)
	}
	history, err := store.ListTransitions(ctx, current.EngagementID, current.DetectionID)
	if err != nil || len(history) != 1 || !history[0].OccurredAt.Equal(received.OccurredAt) {
		t.Fatalf("history after retry = %#v, err=%v; want first received fact", history, err)
	}
}

func TestDetectionProvenanceStoreRejectsConflictingImmutableAdmission(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	current, received := provenanceAdmission("tenant-a", "eng-1", "detection-1", time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC))
	wantPendingInput := append([]byte(nil), current.PendingInput...)
	if err := store.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit pending: %v", err)
	}
	current.PendingInput[0] = 'M'
	stored, found, err := store.Current(ctx, current.EngagementID, current.DetectionID)
	if err != nil {
		t.Fatalf("get stored current: %v", err)
	}
	if !found || string(stored.PendingInput) != string(wantPendingInput) {
		t.Fatalf("stored pending input = %q, found=%t; want %q", stored.PendingInput, found, wantPendingInput)
	}
	stored.PendingInput[0] = 'R'
	stored, found, err = store.Current(ctx, current.EngagementID, current.DetectionID)
	if err != nil || !found || string(stored.PendingInput) != string(wantPendingInput) {
		t.Fatalf("re-read current = %#v, found=%t, err=%v; want preserved pending input", stored, found, err)
	}
	currentRows, err := store.ListCurrent(ctx, current.EngagementID)
	if err != nil || len(currentRows) != 1 || string(currentRows[0].PendingInput) != string(wantPendingInput) {
		t.Fatalf("list current = %#v, err=%v; want preserved pending input", currentRows, err)
	}
	currentRows[0].PendingInput[0] = 'L'
	currentRows, err = store.ListCurrent(ctx, current.EngagementID)
	if err != nil || len(currentRows) != 1 || string(currentRows[0].PendingInput) != string(wantPendingInput) {
		t.Fatalf("re-read list current = %#v, err=%v; want preserved pending input", currentRows, err)
	}
	conflictReceived := received
	conflictReceived.TelemetryRefs = append([]fleetagent.TelemetryReference(nil), received.TelemetryRefs...)
	received.TelemetryRefs[0].Digest = "mutated-input-digest"
	history, err := store.ListTransitions(ctx, current.EngagementID, current.DetectionID)
	if err != nil {
		t.Fatalf("list admission history: %v", err)
	}
	if history[0].TelemetryRefs[0].Digest != "digest-1" {
		t.Fatalf("stored telemetry reference = %#v, want original digest", history[0].TelemetryRefs)
	}
	history[0].TelemetryRefs[0].Digest = "mutated-returned-digest"
	history, err = store.ListTransitions(ctx, current.EngagementID, current.DetectionID)
	if err != nil {
		t.Fatalf("re-read admission history: %v", err)
	}
	if history[0].TelemetryRefs[0].Digest != "digest-1" {
		t.Fatalf("returned telemetry references leaked mutable backing storage: %#v", history[0].TelemetryRefs)
	}

	conflicting := current
	conflicting.PendingInput = []byte("different durable input")
	if err := store.AdmitPending(ctx, conflicting, conflictReceived); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("conflicting admission error = %v, want conflict", err)
	}

	got, found, err := store.Current(ctx, current.EngagementID, current.DetectionID)
	if err != nil {
		t.Fatalf("get current: %v", err)
	}
	if !found || string(got.PendingInput) != string(wantPendingInput) {
		t.Fatalf("current after conflicting admission = %#v, found=%t; want original admission", got, found)
	}
	history, err = store.ListTransitions(ctx, current.EngagementID, current.DetectionID)
	if err != nil || len(history) != 1 {
		t.Fatalf("history after conflicting admission = %#v, err=%v; want one transition", history, err)
	}
}

func TestDetectionProvenanceStoreConcurrentIdenticalTransitionIsIdempotent(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	current, received := provenanceAdmission("tenant-a", "eng-1", "detection-1", time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC))
	if err := store.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit pending: %v", err)
	}
	transition := provenanceTransition(current, detectionprovenance.TelemetryDurable, detectionprovenance.StatusPending, received.OccurredAt.Add(time.Minute))
	transition.TelemetryRefs = []fleetagent.TelemetryReference{{StreamID: "stream-2", Epoch: 1, Sequence: 2, EventID: "event-2", Digest: "digest-2"}}

	const callers = 16
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			errs <- store.AppendTransition(ctx, transition)
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent identical transition: %v", err)
		}
	}

	history, err := store.ListTransitions(ctx, current.EngagementID, current.DetectionID)
	if err != nil {
		t.Fatalf("list transition history: %v", err)
	}
	if len(history) != 2 || history[1].Kind != detectionprovenance.TelemetryDurable || history[1].Sequence != 2 {
		t.Fatalf("transition history = %#v, want received then one durable transition", history)
	}
	transition.TelemetryRefs[0].Digest = "mutated-append-input"
	if history[1].TelemetryRefs[0].Digest != "digest-2" {
		t.Fatalf("stored appended telemetry reference = %#v, want original digest", history[1].TelemetryRefs)
	}
	history[1].TelemetryRefs[0].Digest = "mutated-append-return"
	history, err = store.ListTransitions(ctx, current.EngagementID, current.DetectionID)
	if err != nil || history[1].TelemetryRefs[0].Digest != "digest-2" {
		t.Fatalf("re-read appended transition history = %#v, err=%v; want original digest", history, err)
	}
}

func TestDetectionProvenanceStoreRetriesEarlierTransitionAfterLaterFact(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	current, received := provenanceAdmission("tenant-a", "eng-1", "detection-1", at)
	if err := store.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit pending: %v", err)
	}
	durable := provenanceTransition(current, detectionprovenance.TelemetryDurable, detectionprovenance.StatusPending, at.Add(time.Minute))
	if err := store.AppendTransition(ctx, durable); err != nil {
		t.Fatalf("append durable: %v", err)
	}
	pending := provenanceTransition(current, detectionprovenance.CommitmentPending, detectionprovenance.StatusPending, at.Add(2*time.Minute))
	if err := store.AppendTransition(ctx, pending); err != nil {
		t.Fatalf("append commitment pending: %v", err)
	}
	delayedRetry := durable
	delayedRetry.OccurredAt = at.Add(time.Hour)
	if err := store.AppendTransition(ctx, delayedRetry); err != nil {
		t.Fatalf("retry earlier durable fact: %v", err)
	}
	history, err := store.ListTransitions(ctx, current.EngagementID, current.DetectionID)
	if err != nil || len(history) != 3 || history[1].Kind != detectionprovenance.TelemetryDurable || history[2].Kind != detectionprovenance.CommitmentPending {
		t.Fatalf("history after delayed retry = %#v, err=%v; want no duplicate", history, err)
	}
}

func TestDetectionProvenanceStoreIsTenantIsolated(t *testing.T) {
	store := NewDetectionProvenanceStore()
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	tenantA := shared.WithTenant(t.Context(), "tenant-a")
	tenantB := shared.WithTenant(t.Context(), "tenant-b")
	currentA, receivedA := provenanceAdmission("tenant-a", "eng-1", "detection-1", at)
	currentB, receivedB := provenanceAdmission("tenant-b", "eng-1", "detection-1", at.Add(time.Hour))
	currentB.PendingInput = []byte("tenant-b immutable input")
	receivedB.OccurredAt = at.Add(time.Hour)
	if err := store.AdmitPending(tenantA, currentA, receivedA); err != nil {
		t.Fatalf("admit tenant A: %v", err)
	}
	if err := store.AdmitPending(tenantB, currentB, receivedB); err != nil {
		t.Fatalf("admit tenant B: %v", err)
	}

	if err := store.AppendTransition(tenantA, provenanceTransition(currentA, detectionprovenance.TelemetryDurable, detectionprovenance.StatusPending, at.Add(time.Minute))); err != nil {
		t.Fatalf("append tenant A transition: %v", err)
	}
	current, found, err := store.Current(tenantB, currentB.EngagementID, currentB.DetectionID)
	if err != nil {
		t.Fatalf("get tenant B current: %v", err)
	}
	if !found || current.Status != detectionprovenance.StatusPending || string(current.PendingInput) != "tenant-b immutable input" || !current.UpdatedAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("tenant B current = %#v, found=%t; want tenant B's distinct pending state", current, found)
	}
	history, err := store.ListTransitions(tenantB, currentB.EngagementID, currentB.DetectionID)
	if err != nil || len(history) != 1 || history[0].Kind != detectionprovenance.Received {
		t.Fatalf("tenant B history = %#v, err=%v; want its received transition only", history, err)
	}
}

func TestDetectionProvenanceStoreScopesDetectionIDByEngagement(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	first, firstReceived := provenanceAdmission("tenant-a", "eng-1", "detection-1", at)
	second, secondReceived := provenanceAdmission("tenant-a", "eng-2", "detection-1", at.Add(time.Hour))
	second.PendingInput = []byte("engagement two durable input")
	if err := store.AdmitPending(ctx, first, firstReceived); err != nil {
		t.Fatalf("admit first engagement: %v", err)
	}
	if err := store.AdmitPending(ctx, second, secondReceived); err != nil {
		t.Fatalf("admit second engagement: %v", err)
	}
	if err := store.AppendTransition(ctx, provenanceTransition(first, detectionprovenance.TelemetryDurable, detectionprovenance.StatusPending, at.Add(time.Minute))); err != nil {
		t.Fatalf("advance first engagement: %v", err)
	}
	got, found, err := store.Current(ctx, second.EngagementID, second.DetectionID)
	if err != nil || !found || got.Status != detectionprovenance.StatusPending || string(got.PendingInput) != string(second.PendingInput) || !got.UpdatedAt.Equal(second.UpdatedAt) {
		t.Fatalf("second engagement current = %#v, found=%t, err=%v; want independent state", got, found, err)
	}
	history, err := store.ListTransitions(ctx, second.EngagementID, second.DetectionID)
	if err != nil || len(history) != 1 || history[0].Kind != detectionprovenance.Received {
		t.Fatalf("second engagement history = %#v, err=%v; want received only", history, err)
	}
}

func TestDetectionProvenanceStoreReturnsDeterministicOrderedReads(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	lateCurrent, lateReceived := provenanceAdmission("tenant-a", "eng-1", "detection-z", at)
	earlyCurrent, earlyReceived := provenanceAdmission("tenant-a", "eng-1", "detection-a", at)
	if err := store.AdmitPending(ctx, lateCurrent, lateReceived); err != nil {
		t.Fatalf("admit late detection: %v", err)
	}
	if err := store.AdmitPending(ctx, earlyCurrent, earlyReceived); err != nil {
		t.Fatalf("admit early detection: %v", err)
	}
	wantCurrent := earlyCurrent
	requireProvenanceCurrent(t, store, ctx, wantCurrent)

	durable := provenanceTransition(earlyCurrent, detectionprovenance.TelemetryDurable, detectionprovenance.StatusPending, at.Add(time.Minute))
	if err := store.AppendTransition(ctx, durable); err != nil {
		t.Fatalf("append durable transition: %v", err)
	}
	wantCurrent.UpdatedAt = durable.OccurredAt
	requireProvenanceCurrent(t, store, ctx, wantCurrent)

	pending := provenanceTransition(earlyCurrent, detectionprovenance.CommitmentPending, detectionprovenance.StatusPending, at.Add(2*time.Minute))
	if err := store.AppendTransition(ctx, pending); err != nil {
		t.Fatalf("append pending commitment transition: %v", err)
	}
	wantCurrent.UpdatedAt = pending.OccurredAt
	requireProvenanceCurrent(t, store, ctx, wantCurrent)

	sealed := provenanceTransition(earlyCurrent, detectionprovenance.CommitmentSealed, detectionprovenance.StatusPending, at.Add(3*time.Minute))
	sealed.EvidenceID = "evidence-1"
	if err := store.AppendTransition(ctx, sealed); err != nil {
		t.Fatalf("append sealed commitment transition: %v", err)
	}
	wantCurrent.EvidenceID = sealed.EvidenceID
	wantCurrent.UpdatedAt = sealed.OccurredAt
	requireProvenanceCurrent(t, store, ctx, wantCurrent)

	acknowledged := provenanceTransition(earlyCurrent, detectionprovenance.Acknowledged, detectionprovenance.StatusComplete, at.Add(4*time.Minute))
	acknowledged.EvidenceID = "evidence-1"
	if err := store.AppendTransition(ctx, acknowledged); err != nil {
		t.Fatalf("append acknowledged transition: %v", err)
	}
	wantCurrent.Status = detectionprovenance.StatusComplete
	wantCurrent.UpdatedAt = acknowledged.OccurredAt
	requireProvenanceCurrent(t, store, ctx, wantCurrent)

	current, err := store.ListCurrent(ctx, "eng-1")
	if err != nil {
		t.Fatalf("list current: %v", err)
	}
	wantCurrentList := []detectionprovenance.Current{wantCurrent, lateCurrent}
	if !reflect.DeepEqual(current, wantCurrentList) {
		t.Fatalf("current = %#v, want %#v", current, wantCurrentList)
	}
	history, err := store.ListTransitions(ctx, earlyCurrent.EngagementID, earlyCurrent.DetectionID)
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	durable.Sequence = 2
	pending.Sequence = 3
	sealed.Sequence = 4
	acknowledged.Sequence = 5
	wantHistory := []detectionprovenance.Transition{earlyReceived, durable, pending, sealed, acknowledged}
	for i := range wantHistory {
		if !detectionprovenance.EquivalentTransition(history[i], wantHistory[i]) {
			t.Fatalf("history[%d] = %#v, want semantic transition %#v", i, history[i], wantHistory[i])
		}
	}
	if err := detectionprovenance.VerifyChain(history); err != nil {
		t.Fatalf("verify persisted provenance chain: %v", err)
	}
}

func TestDetectionProvenanceStoreFailsClosedOnTamperedHistory(t *testing.T) {
	store := NewDetectionProvenanceStore()
	ctx := shared.WithTenant(t.Context(), "tenant-a")
	at := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	current, received := provenanceAdmission("tenant-a", "eng-1", "detection-1", at)
	if err := store.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit provenance: %v", err)
	}

	key := provenanceKey{engagement: current.EngagementID, detection: current.DetectionID}
	store.mu.Lock()
	history := store.transitions[current.TenantID][key]
	history[0].Reason = "tampered"
	store.transitions[current.TenantID][key] = history
	store.mu.Unlock()

	if _, err := store.ListTransitions(ctx, current.EngagementID, current.DetectionID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("read tampered provenance error = %v, want conflict", err)
	}
	durable := provenanceTransition(current, detectionprovenance.TelemetryDurable, detectionprovenance.StatusPending, at.Add(time.Minute))
	if err := store.AppendTransition(ctx, durable); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("append after tampering error = %v, want conflict", err)
	}
	laterCurrent, laterReceived := current, received
	laterCurrent.UpdatedAt = laterCurrent.UpdatedAt.Add(time.Hour)
	laterReceived.OccurredAt = laterReceived.OccurredAt.Add(time.Hour)
	if err := store.AdmitPending(ctx, laterCurrent, laterReceived); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("retry after tampering error = %v, want conflict", err)
	}
}
