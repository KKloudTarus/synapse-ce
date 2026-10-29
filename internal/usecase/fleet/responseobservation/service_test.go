package responseobservation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
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

type testSignerStore struct {
	signer Signer
	hook   func()
}

func (s testSignerStore) EnsureResponseVerificationSigner(shared.ID, time.Time) (Signer, error) {
	if s.hook != nil {
		s.hook()
	}
	return s.signer, nil
}

type testOutbox struct {
	report              fleetagent.ResponseVerificationReport
	found, acknowledged bool
	loadHook, saveHook  func()
}

func (o *testOutbox) LoadResponseVerificationReport(string) (fleetagent.ResponseVerificationReport, bool, error) {
	if o.loadHook != nil {
		o.loadHook()
	}
	return o.report, o.found, nil
}
func (o *testOutbox) SaveResponseVerificationReport(report fleetagent.ResponseVerificationReport) error {
	o.report, o.found = report, true
	if o.saveHook != nil {
		o.saveHook()
	}
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
	hook   func()
	err    error
}

func (r *testReports) ShipResponseVerification(_ context.Context, report fleetagent.ResponseVerificationReport) error {
	r.report = report
	if r.hook != nil {
		r.hook()
	}
	return r.err
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
		Target:   responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "assigned-target-asset", ProcessEntityID: "pe_11111111111111111111111111111111"},
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
	if err := service.Observe(context.Background(), "observer-1", "assigned-target-asset", "assigned-target-asset", WorkOrder{LeaseUntil: now.Add(time.Minute)}); err != nil {
		t.Fatalf("identity failure reports terminal state, got %v", err)
	}
	if work.state != workorder.StateRefused {
		t.Fatalf("identity mismatch state = %s", work.state)
	}
}

func observationFixture(t *testing.T) (fleetagent.ResponseObservationRequest, Signer, *testClock) {
	t.Helper()
	now := time.Unix(2_000_000, 0).UTC()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	key, err := fleetagent.NewSigningKey("observer-1", fleetagent.PurposeResponseResult, private.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	request := fleetagent.ResponseObservationRequest{
		ProtocolVersion: fleetagent.ResponseObservationProtocolVersion, RequestID: "order-1", TenantID: "tenant-1", ObserverAgentID: "observer-1", AssetID: "target-1", EngagementID: "engagement-1", ActionID: "action-1",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-1", VerificationChallenge: strings.Repeat("b", 64), ReceiptID: "receipt-1", ReceiptDigest: strings.Repeat("c", 64),
		Target: responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "target-1", ProcessEntityID: "pe_11111111111111111111111111111111"}, AttemptedAt: now.Add(-time.Second), IssuedAt: now, NotAfter: now.Add(time.Minute),
	}
	return request, Signer{PrivateKey: private, Key: key}, &testClock{now: now}
}

func TestObserveLeaseBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		lease                   time.Duration
		zero, malformed, future bool
		want                    workorder.State
		forbidden               bool
	}{
		{name: "short lease", lease: time.Second, want: workorder.StateSucceeded},
		{name: "zero lease", zero: true, forbidden: true},
		{name: "expired lease", lease: -time.Second, forbidden: true},
		{name: "malformed request", lease: time.Second, malformed: true, want: workorder.StateRefused},
		{name: "future request", lease: time.Second, future: true, forbidden: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, signer, clock := observationFixture(t)
			if tc.malformed {
				request.ActionDigest = "bad"
			}
			if tc.future {
				request.IssuedAt = clock.now.Add(time.Second)
			}
			lease := clock.now.Add(tc.lease)
			if tc.zero {
				lease = time.Time{}
			}
			outbox, registrar, reports, work := &testOutbox{}, &testRegistrar{}, &testReports{}, &testWork{}
			service, err := NewService(testSignerStore{signer: signer}, outbox, registrar, reports, work, clock, 0)
			if err != nil {
				t.Fatal(err)
			}
			err = service.Observe(context.Background(), "observer-1", "observer-primary", "target-1", WorkOrder{ID: request.RequestID, AssetID: request.AssetID, LeaseID: "lease-1", LeaseUntil: lease, Request: &request})
			if tc.forbidden && !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("got %v, want forbidden", err)
			}
			if !tc.forbidden && err != nil {
				t.Fatal(err)
			}
			if work.state != tc.want {
				t.Fatalf("state=%q want=%q", work.state, tc.want)
			}
			if tc.forbidden && (work.progressed || work.state != "" || outbox.found || registrar.registered.KeyID != "" || reports.report.ReportID != "") {
				t.Fatal("expired or future work caused an effect")
			}
		})
	}
}

func TestObserveStopsAfterSynchronousBoundaryExpires(t *testing.T) {
	for _, step := range []string{"load", "signer", "save", "ship", "cancel"} {
		t.Run(step, func(t *testing.T) {
			request, signer, clock := observationFixture(t)
			outbox, registrar, reports, work := &testOutbox{}, &testRegistrar{}, &testReports{}, &testWork{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expire := func() { clock.now = clock.now.Add(2 * time.Second) }
			signers := testSignerStore{signer: signer}
			switch step {
			case "load":
				outbox.loadHook = expire
			case "signer":
				signers.hook = expire
			case "save":
				outbox.saveHook = expire
			case "ship":
				reports.hook = expire
			case "cancel":
				outbox.loadHook = cancel
			}
			service, err := NewService(signers, outbox, registrar, reports, work, clock, 0)
			if err != nil {
				t.Fatal(err)
			}
			err = service.Observe(ctx, "observer-1", "observer-primary", "target-1", WorkOrder{ID: request.RequestID, AssetID: request.AssetID, LeaseID: "lease-1", LeaseUntil: clock.now.Add(time.Second), Request: &request})
			if err == nil {
				t.Fatal("expected expired operation")
			}
			if work.state != "" || outbox.acknowledged {
				t.Fatal("expired operation submitted result or acknowledged report")
			}
			if step != "ship" && reports.report.ReportID != "" {
				t.Fatal("shipped after expiry")
			}
			if (step == "load" || step == "signer" || step == "cancel") && outbox.found {
				t.Fatal("signed report after expiry")
			}
		})
	}
}

func TestObserveReclaimPreservesSignedReport(t *testing.T) {
	request, signer, clock := observationFixture(t)
	outbox, registrar, reports, work := &testOutbox{}, &testRegistrar{}, &testReports{err: errors.New("temporary failure")}, &testWork{}
	service, err := NewService(testSignerStore{signer: signer}, outbox, registrar, reports, work, clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	order := WorkOrder{ID: request.RequestID, AssetID: request.AssetID, LeaseID: "lease-1", LeaseUntil: clock.now.Add(time.Second), Request: &request}
	if err := service.Observe(context.Background(), "observer-1", "observer-primary", "target-1", order); err == nil || !outbox.found {
		t.Fatal("expected retained report after temporary delivery failure")
	}
	original := outbox.report
	clock.now = clock.now.Add(2 * time.Second)
	order.LeaseID = "lease-2"
	order.LeaseUntil = clock.now.Add(time.Second)
	reports.err = nil
	if err := service.Observe(context.Background(), "observer-1", "observer-primary", "target-1", order); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, reports.report) || work.state != workorder.StateSucceeded || !outbox.acknowledged {
		t.Fatal("reclaim did not ship the original signed report")
	}
}
