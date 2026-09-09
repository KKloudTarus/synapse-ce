package responseobserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fakeAPI struct {
	registered int
	report     fleetagent.ResponseVerificationReport
	shipErr    error
	progressed bool
	result     workorder.State
}

func (f *fakeAPI) RegisterSigningKey(context.Context, string, fleetagent.AgentSigningKey, string) error {
	f.registered++
	return nil
}

func (f *fakeAPI) ShipResponseVerification(_ context.Context, _ string, report fleetagent.ResponseVerificationReport) (fleetclient.ResponseVerificationShipResponse, error) {
	f.report = report
	if f.shipErr != nil {
		return fleetclient.ResponseVerificationShipResponse{}, f.shipErr
	}
	return fleetclient.ResponseVerificationShipResponse{Acknowledged: true, ReportID: report.ReportID}, nil
}

func (f *fakeAPI) Progress(context.Context, string, string, string) error {
	f.progressed = true
	return nil
}

func (f *fakeAPI) SubmitResult(_ context.Context, _ string, _ string, _ string, state string, _ string) error {
	f.result = workorder.State(state)
	return nil
}

func testRequest(now time.Time) fleetagent.ResponseObservationRequest {
	return fleetagent.ResponseObservationRequest{
		ProtocolVersion:       fleetagent.ResponseObservationProtocolVersion,
		RequestID:             "request-1",
		TenantID:              "tenant-1",
		ObserverAgentID:       "observer-1",
		AssetID:               "target-asset-1",
		EngagementID:          "engagement-1",
		ActionID:              "action-1",
		ActionDigest:          strings.Repeat("a", 64),
		AttemptKey:            "attempt-1",
		VerificationChallenge: strings.Repeat("b", 64),
		ReceiptID:             "receipt-1",
		ReceiptDigest:         strings.Repeat("c", 64),
		Target: responsesaga.TargetFingerprint{
			Kind: responsesaga.FingerprintProcess, ProcessAssetID: "target-asset-1", ProcessEntityID: "process-1",
		},
		AttemptedAt: now.Add(-time.Second),
		IssuedAt:    now,
		NotAfter:    now.Add(time.Minute),
	}
}

func TestObserveDiscardsOutboxOnlyForPermanentRefusal(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	for _, test := range []struct {
		name      string
		shipErr   error
		wantFound bool
	}{
		{name: "privacy erased", shipErr: &fleetclient.HTTPStatusError{StatusCode: http.StatusGone}},
		{name: "authorization failure", shipErr: &fleetclient.HTTPStatusError{StatusCode: http.StatusForbidden}, wantFound: true},
		{name: "network failure", shipErr: errors.New("network unavailable"), wantFound: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := testRequest(now)
			order := fleetclient.Order{ID: request.RequestID.String(), AssetID: request.AssetID.String(), LeaseID: "lease-1", LeaseUntil: request.NotAfter, ResponseObserve: &request}
			credential := fleetclient.Credential{AgentID: request.ObserverAgentID.String(), AssetID: "primary-asset-1", ResponseObserverAssetID: request.AssetID.String(), Token: "token"}
			store := fleetclient.NewCredentialStore(t.TempDir())
			api := &fakeAPI{shipErr: test.shipErr}
			runtime, err := NewWithClock(store, api, 0, fixedClock{now: now})
			if err != nil {
				t.Fatal(err)
			}

			err = runtime.Observe(context.Background(), credential, order)
			if err == nil || !strings.Contains(err.Error(), "ship response observation") {
				t.Fatalf("Observe() error = %v, want shipping error", err)
			}
			_, found, err := store.LoadResponseVerificationReport(request.AttemptKey)
			if err != nil {
				t.Fatal(err)
			}
			if found != test.wantFound {
				t.Fatalf("outbox found=%t, want %t", found, test.wantFound)
			}
			if !api.progressed || api.registered != 1 || api.report.AttemptKey != request.AttemptKey {
				t.Fatalf("observation flow = progressed=%t registered=%d report=%+v", api.progressed, api.registered, api.report)
			}
		})
	}
}

func TestNewWithClockRequiresCompleteDependencies(t *testing.T) {
	store := fleetclient.NewCredentialStore(t.TempDir())
	api := &fakeAPI{}
	for _, test := range []struct {
		name  string
		store *fleetclient.CredentialStore
		api   API
		delay time.Duration
		clock ports.Clock
	}{
		{name: "nil store", api: api, delay: time.Second, clock: fixedClock{now: time.Now()}},
		{name: "nil api", store: store, delay: time.Second, clock: fixedClock{now: time.Now()}},
		{name: "nil clock", store: store, api: api, delay: time.Second},
		{name: "negative delay", store: store, api: api, delay: -time.Second, clock: fixedClock{now: time.Now()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewWithClock(test.store, test.api, test.delay, test.clock); err == nil {
				t.Fatal("NewWithClock() error = nil")
			}
		})
	}
}

var _ API = (*fakeAPI)(nil)
