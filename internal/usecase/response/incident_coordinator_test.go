package response

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/incidentuc"
)

type fakeIncidentResponseApplier struct {
	prepare    func(context.Context, shared.ID, rdom.Action, engagement.Target, responsesaga.TargetFingerprint, string) (Record, error)
	apply      func(context.Context, shared.ID, rdom.Action, engagement.Target, responsesaga.TargetFingerprint, string) (Record, error)
	provenance VerificationProvenance
	provErr    error
	provCalls  int
}

func (f *fakeIncidentResponseApplier) PrepareIncidentResponse(ctx context.Context, engagementID shared.ID, action rdom.Action, target engagement.Target, fingerprint responsesaga.TargetFingerprint, actor string) (Record, error) {
	if f.prepare != nil {
		return f.prepare(ctx, engagementID, action, target, fingerprint, actor)
	}
	return Record{ID: action.ID, EngagementID: engagementID, Action: action, State: StatePending}, nil
}

func (f *fakeIncidentResponseApplier) Apply(ctx context.Context, engagementID shared.ID, action rdom.Action, target engagement.Target, fingerprint responsesaga.TargetFingerprint, actor string) (Record, error) {
	return f.apply(ctx, engagementID, action, target, fingerprint, actor)
}

func (f *fakeIncidentResponseApplier) VerifiedProvenance(context.Context, shared.ID) (VerificationProvenance, error) {
	f.provCalls++
	return f.provenance, f.provErr
}

type conflictOnceIncidentAppender struct {
	inner     *incidentuc.Service
	conflicts int
}

func (a *conflictOnceIncidentAppender) Get(ctx context.Context, id shared.ID) (incident.Incident, error) {
	return a.inner.Get(ctx, id)
}

func (a *conflictOnceIncidentAppender) Append(ctx context.Context, id shared.ID, revision int, events []incident.IncidentEvent) (incident.Incident, error) {
	if a.conflicts > 0 {
		a.conflicts--
		return incident.Incident{}, shared.ErrConflict
	}
	return a.inner.Append(ctx, id, revision, events)
}

func (a *conflictOnceIncidentAppender) ListPendingResponseLinks(ctx context.Context) ([]incident.ResponseLink, error) {
	return a.inner.ListPendingResponseLinks(ctx)
}

func seededIncidentService(t *testing.T, now time.Time) *incidentuc.Service {
	t.Helper()
	service, err := incidentuc.NewService(memory.NewIncidentEventStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(tctx(), "inc-1", 0, []incident.IncidentEvent{{
		IncidentID: "inc-1", Kind: incident.EventCreated, At: now, Actor: "correlator",
		AssetID: "asset-1", Title: "malicious process", Severity: shared.SeverityHigh,
	}}); err != nil {
		t.Fatal(err)
	}
	return service
}

func TestIncidentCoordinatorPersistsRequestBeforeApplyAndVerifiedProvenance(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	incidents := seededIncidentService(t, now)
	action, err := rdom.NewAction("response-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	target := engagement.Target{Kind: engagement.TargetDomain, Value: action.Target.String()}
	fingerprint := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: action.Target}
	provenance := VerificationProvenance{
		ActionID: action.ID, EngagementID: "eng-1", ActionDigest: responseActionDigest(action), Target: fingerprint,
		AttemptKey: "attempt-1", ExecutorID: "agent:executor", VerifierID: "control-plane:response-verifier", EvidenceID: "evidence-1",
	}
	fake := &fakeIncidentResponseApplier{provenance: provenance}
	prepared := false
	fake.prepare = func(_ context.Context, engagementID shared.ID, action rdom.Action, _ engagement.Target, _ responsesaga.TargetFingerprint, _ string) (Record, error) {
		prepared = true
		return Record{ID: action.ID, EngagementID: engagementID, Action: action, State: StatePending}, nil
	}
	applyCalls := 0
	fake.apply = func(ctx context.Context, _ shared.ID, action rdom.Action, _ engagement.Target, _ responsesaga.TargetFingerprint, _ string) (Record, error) {
		applyCalls++
		if !prepared {
			t.Fatal("incident request reached Apply before the live action was prepared")
		}
		current, err := incidents.Get(ctx, "inc-1")
		if err != nil {
			t.Fatal(err)
		}
		if len(current.Responses) != 1 || current.Responses[0].ActionID != action.ID || (applyCalls == 1 && current.Responses[0].Verified) {
			t.Fatalf("response request was not durable before Apply: %+v", current.Responses)
		}
		return Record{ID: action.ID, EngagementID: "eng-1", Action: action, State: StateApplied, Verification: VerificationSucceeded}, nil
	}
	coordinator, err := NewIncidentCoordinator(fake, &conflictOnceIncidentAppender{inner: incidents, conflicts: 1}, fixedClock{t: now})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		if _, err := coordinator.Apply(tctx(), "inc-1", "eng-1", action, target, fingerprint, "alice"); err != nil {
			t.Fatalf("apply attempt %d: %v", i+1, err)
		}
	}
	linked, err := incidents.Get(tctx(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if linked.Revision != 3 || len(linked.Responses) != 1 {
		t.Fatalf("retries must not duplicate incident events: %+v", linked)
	}
	ref := linked.Responses[0]
	if !ref.Verified || ref.AttemptKey != provenance.AttemptKey || ref.ExecutorID != provenance.ExecutorID ||
		ref.VerifierID != provenance.VerifierID || ref.EvidenceID != provenance.EvidenceID {
		t.Fatalf("verified incident reference lost provenance: %+v", ref)
	}
	if fake.provCalls != 2 {
		t.Fatalf("each successful Apply must reload durable provenance, got %d calls", fake.provCalls)
	}
}

func TestIncidentCoordinatorDoesNotAppendRequestWhenActionPreparationFails(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	incidents := seededIncidentService(t, now)
	action, err := rdom.NewAction("response-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	target := engagement.Target{Kind: engagement.TargetDomain, Value: action.Target.String()}
	fingerprint := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: action.Target}
	prepareErr := errors.New("action store unavailable")
	fake := &fakeIncidentResponseApplier{
		prepare: func(context.Context, shared.ID, rdom.Action, engagement.Target, responsesaga.TargetFingerprint, string) (Record, error) {
			return Record{}, prepareErr
		},
		apply: func(context.Context, shared.ID, rdom.Action, engagement.Target, responsesaga.TargetFingerprint, string) (Record, error) {
			t.Fatal("failed action preparation reached Apply")
			return Record{}, nil
		},
	}
	coordinator, err := NewIncidentCoordinator(fake, incidents, fixedClock{t: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Apply(tctx(), "inc-1", "eng-1", action, target, fingerprint, "alice"); !errors.Is(err, prepareErr) {
		t.Fatalf("preparation error=%v, want %v", err, prepareErr)
	}
	current, err := incidents.Get(tctx(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 1 || len(current.Responses) != 0 {
		t.Fatalf("failed preparation appended an incident response request: %+v", current)
	}
}

func TestIncidentCoordinatorReconcilesOnlyPersistedVerifiedResponse(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	incidents := seededIncidentService(t, now)
	action, err := rdom.NewAction("response-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	target := engagement.Target{Kind: engagement.TargetDomain, Value: action.Target.String()}
	fingerprint := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: action.Target}
	fake := &fakeIncidentResponseApplier{
		apply: func(context.Context, shared.ID, rdom.Action, engagement.Target, responsesaga.TargetFingerprint, string) (Record, error) {
			return Record{ID: action.ID, EngagementID: "eng-1", Action: action, State: StateApplied, Verification: VerificationUnknown}, nil
		},
		provenance: VerificationProvenance{
			ActionID: action.ID, EngagementID: "eng-1", ActionDigest: responseActionDigest(action), Target: fingerprint,
			AttemptKey: "attempt-1", ExecutorID: "agent:executor", VerifierID: "control-plane:response-verifier", EvidenceID: "evidence-1",
		},
	}
	coordinator, err := NewIncidentCoordinator(fake, incidents, fixedClock{t: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Apply(tctx(), "inc-1", "eng-1", action, target, fingerprint, "alice"); err != nil {
		t.Fatalf("request-only apply: %v", err)
	}
	before, err := incidents.Get(tctx(), "inc-1")
	if err != nil || before.Revision != 2 || before.Responses[0].Verified {
		t.Fatalf("request must remain unverified before reconciliation: %+v err=%v", before, err)
	}

	if err := coordinator.ReconcileIncidentLinks(tctx()); err != nil {
		t.Fatalf("reconcile verified linkage: %v", err)
	}
	after, err := incidents.Get(tctx(), "inc-1")
	if err != nil || after.Revision != 3 || !after.Responses[0].Verified {
		t.Fatalf("reconciliation must append one verified event: %+v err=%v", after, err)
	}
	if fake.provCalls != 1 {
		t.Fatalf("reconciliation provenance calls = %d, want 1", fake.provCalls)
	}
	if err := coordinator.ReconcileIncidentLinks(tctx()); err != nil {
		t.Fatalf("idempotent reconciliation: %v", err)
	}
	final, err := incidents.Get(tctx(), "inc-1")
	if err != nil || final.Revision != 3 || fake.provCalls != 1 {
		t.Fatalf("idempotent reconciliation duplicated event or provenance read: %+v calls=%d err=%v", final, fake.provCalls, err)
	}
}

func TestIncidentCoordinatorRejectsMachineVerificationProvenance(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	incidents := seededIncidentService(t, now)
	action, err := rdom.NewAction("response-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	target := engagement.Target{Kind: engagement.TargetDomain, Value: action.Target.String()}
	fingerprint := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: action.Target}
	fake := &fakeIncidentResponseApplier{
		apply: func(context.Context, shared.ID, rdom.Action, engagement.Target, responsesaga.TargetFingerprint, string) (Record, error) {
			return Record{ID: action.ID, EngagementID: "eng-1", Action: action, State: StateApplied, Verification: VerificationSucceeded}, nil
		},
		provenance: VerificationProvenance{
			ActionID: action.ID, EngagementID: "eng-1", ActionDigest: responseActionDigest(action), Target: fingerprint,
			AttemptKey: "attempt-1", ExecutorID: "agent:executor", VerifierID: "agent:verifier", EvidenceID: "evidence-1",
		},
	}
	coordinator, err := NewIncidentCoordinator(fake, incidents, fixedClock{t: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Apply(tctx(), "inc-1", "eng-1", action, target, fingerprint, "alice"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("machine verifier must be rejected, got %v", err)
	}
	linked, err := incidents.Get(tctx(), "inc-1")
	if err != nil || linked.Revision != 2 || linked.Responses[0].Verified {
		t.Fatalf("machine provenance must leave request unverified: %+v err=%v", linked, err)
	}
}

func TestIncidentCoordinatorDoesNotVerifyUnknownResponse(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	incidents := seededIncidentService(t, now)
	action, err := rdom.NewAction("response-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	target := engagement.Target{Kind: engagement.TargetDomain, Value: action.Target.String()}
	fingerprint := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: action.Target}
	applyErr := errors.New("verification unavailable")
	fake := &fakeIncidentResponseApplier{apply: func(context.Context, shared.ID, rdom.Action, engagement.Target, responsesaga.TargetFingerprint, string) (Record, error) {
		return Record{ID: action.ID, EngagementID: "eng-1", Action: action, State: StateApplied, Verification: VerificationUnknown}, applyErr
	}}
	coordinator, err := NewIncidentCoordinator(fake, incidents, fixedClock{t: now})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := coordinator.Apply(tctx(), "inc-1", "eng-1", action, target, fingerprint, "alice"); !errors.Is(err, applyErr) {
		t.Fatalf("Apply error must be preserved, got %v", err)
	}
	linked, err := incidents.Get(tctx(), "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if linked.Revision != 2 || len(linked.Responses) != 1 || linked.Responses[0].Verified {
		t.Fatalf("unknown response must remain requested-only: %+v", linked)
	}
	if fake.provCalls != 0 {
		t.Fatal("unknown response must not request successful verification provenance")
	}
}
