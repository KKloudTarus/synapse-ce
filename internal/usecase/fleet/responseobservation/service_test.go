package responseobservation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
)

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

type testSignerStore struct{ signer Signer }

func (s testSignerStore) EnsureResponseVerificationSigner(shared.ID, time.Time) (Signer, error) {
	return s.signer, nil
}

type testOutbox struct {
	report              fleetagent.ResponseVerificationReport
	found, acknowledged bool
}

func (o *testOutbox) LoadResponseVerificationReport(string) (fleetagent.ResponseVerificationReport, bool, error) {
	return o.report, o.found, nil
}
func (o *testOutbox) SaveResponseVerificationReport(report fleetagent.ResponseVerificationReport) error {
	o.report, o.found = report, true
	return nil
}
func (o *testOutbox) AcknowledgeResponseVerificationReport(string) error {
	o.acknowledged = true
	o.found = false
	return nil
}

type testRegistrar struct{ registered fleetagent.AgentSigningKey }

func (r *testRegistrar) RegisterSigningKey(_ context.Context, key fleetagent.AgentSigningKey, _ string) error {
	r.registered = key
	return nil
}

type testReports struct {
	report fleetagent.ResponseVerificationReport
}

func (r *testReports) ShipResponseVerification(_ context.Context, report fleetagent.ResponseVerificationReport) error {
	r.report = report
	return nil
}

type testWork struct {
	progressed bool
	state      workorder.State
}

func (w *testWork) Progress(context.Context, shared.ID, string) error {
	w.progressed = true
	return nil
}
func (w *testWork) SubmitResult(_ context.Context, _ shared.ID, _ string, state workorder.State, _ string) error {
	w.state = state
	return nil
}

type testTelemetry struct {
	agent, primary shared.ID
	request        fleetagent.ResponseObservationRequest
	observation    fleetagent.ResponseObservation
}

func (t *testTelemetry) ShipResponseObservationTelemetry(_ context.Context, agent, primary shared.ID, request fleetagent.ResponseObservationRequest, observation fleetagent.ResponseObservation, _ time.Time) error {
	t.agent, t.primary, t.request, t.observation = agent, primary, request, observation
	return nil
}

type testProcesses struct{}

func (testProcesses) ObservationFor(request fleetagent.ResponseObservationRequest) (fleetagent.ResponseObservation, bool) {
	target := fleetagent.BoundedProcessObservation{BootID: "boot-1", OccurredAt: request.AttemptedAt.Add(time.Millisecond), ObservedAt: request.AttemptedAt.Add(time.Millisecond), Process: telemetry.ProcessObservation{Kind: "exit", PID: 1, StartTimeNanos: 1, EntityID: request.Target.ProcessEntityID, Comm: "service"}}
	replacement := fleetagent.BoundedProcessObservation{BootID: "boot-1", OccurredAt: request.AttemptedAt.Add(2 * time.Millisecond), ObservedAt: request.AttemptedAt.Add(2 * time.Millisecond), Process: telemetry.ProcessObservation{Kind: "exec", PID: 2, StartTimeNanos: 2, EntityID: "replacement-1", Comm: "service"}}
	if request.Reversal {
		return fleetagent.ResponseObservation{TargetExit: target, Replacement: &replacement}, true
	}
	return fleetagent.ResponseObservation{TargetExit: target}, true
}

func TestObserveKeepsPrimaryIdentitySeparateFromTargetTelemetry(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey("observer-1", fleetagent.PurposeResponseResult, private.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	request := fleetagent.ResponseObservationRequest{
		ProtocolVersion: fleetagent.ResponseObservationProtocolVersion, RequestID: "observation-order-1", TenantID: "tenant-1",
		ObserverAgentID: "observer-1", AssetID: "assigned-target-asset", EngagementID: "engagement-1", ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("b", 64), ReceiptID: "receipt-1", ReceiptDigest: strings.Repeat("c", 64),
		Target:   responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "assigned-target-asset", ProcessEntityID: "process-1"},
		Reversal: true, AttemptedAt: now.Add(-time.Second), IssuedAt: now, NotAfter: now.Add(time.Minute),
	}
	outbox := &testOutbox{}
	registrar := &testRegistrar{}
	reports := &testReports{}
	work := &testWork{}
	service, err := NewService(testSignerStore{signer: Signer{PrivateKey: private, Key: key}}, outbox, registrar, reports, work, testClock{now: now}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Observe(context.Background(), "observer-1", "observer-primary-asset", "assigned-target-asset", WorkOrder{ID: request.RequestID, AssetID: request.AssetID, LeaseID: "lease-1", LeaseUntil: request.NotAfter, Request: &request}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if registrar.registered.Purpose != fleetagent.PurposeResponseResult || reports.report.ReportID != request.RequestID || !reports.report.ReplacementProcessEntityID.IsZero() {
		t.Fatalf("signed report flow = key=%+v report=%+v", registrar.registered, reports.report)
	}
	if !work.progressed || work.state != workorder.StateSucceeded || !outbox.acknowledged {
		t.Fatalf("work/outbox state = progressed=%t state=%s acknowledged=%t", work.progressed, work.state, outbox.acknowledged)
	}
}

func TestObserveRejectsTargetAsPrimaryIdentity(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey("observer-1", fleetagent.PurposeResponseResult, private.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	work := &testWork{}
	service, err := NewService(testSignerStore{signer: Signer{PrivateKey: private, Key: key}}, &testOutbox{}, &testRegistrar{}, &testReports{}, work, testClock{now: now}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Observe(context.Background(), "observer-1", "assigned-target-asset", "assigned-target-asset", WorkOrder{}); err != nil {
		t.Fatalf("identity failure reports terminal state, got %v", err)
	}
	if work.state != workorder.StateFailed {
		t.Fatalf("identity mismatch state = %s", work.state)
	}
}
