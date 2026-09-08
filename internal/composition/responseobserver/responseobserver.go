// Package responseobserver composes the agent-side response-observation workflow.
package responseobserver

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	observationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseobservation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// API is the fleet transport required by independent response observation.
type API interface {
	RegisterSigningKey(context.Context, string, fleetagent.AgentSigningKey, string) error
	ShipResponseVerification(context.Context, string, fleetagent.ResponseVerificationReport) (fleetclient.ResponseVerificationShipResponse, error)
	Progress(context.Context, string, string, string) error
	SubmitResult(context.Context, string, string, string, string, string) error
}

// Runtime owns the concrete durable state and fleet adapters used by one agent process.
type Runtime struct {
	store *fleetclient.CredentialStore
	api   API
	delay time.Duration
	clock ports.Clock
}

// New constructs the response-observation runtime using the system clock.
func New(store *fleetclient.CredentialStore, api API, delay time.Duration) (*Runtime, error) {
	return NewWithClock(store, api, delay, idgen.SystemClock{})
}

// NewWithClock constructs the response-observation runtime with an injected clock for tests.
func NewWithClock(store *fleetclient.CredentialStore, api API, delay time.Duration, clock ports.Clock) (*Runtime, error) {
	if store == nil || api == nil || clock == nil || delay < 0 {
		return nil, fmt.Errorf("response observer runtime has an incomplete dependency")
	}
	return &Runtime{store: store, api: api, delay: delay, clock: clock}, nil
}

// Observe executes one server-addressed response-observation order.
func (r *Runtime) Observe(ctx context.Context, credential fleetclient.Credential, order fleetclient.Order) error {
	if r == nil {
		return fmt.Errorf("response observer runtime is not configured")
	}
	transport := fleetTransport{api: r.api, token: credential.Token}
	service, err := observationuc.NewService(
		signerStore{store: r.store},
		outbox{store: r.store},
		transport,
		transport,
		workReporter{api: r.api, token: credential.Token},
		r.clock,
		r.delay,
	)
	if err != nil {
		return fmt.Errorf("configure response observation service: %w", err)
	}
	return service.Observe(
		ctx,
		shared.ID(credential.AgentID),
		shared.ID(credential.AssetID),
		shared.ID(credential.ResponseObserverAssetID),
		observationuc.WorkOrder{
			ID:         shared.ID(order.ID),
			AssetID:    shared.ID(order.AssetID),
			LeaseID:    order.LeaseID,
			LeaseUntil: order.LeaseUntil,
			Request:    order.ResponseObserve,
		},
	)
}

type signerStore struct{ store *fleetclient.CredentialStore }

func (s signerStore) EnsureResponseVerificationSigner(agentID shared.ID, now time.Time) (observationuc.Signer, error) {
	signer, err := s.store.EnsureResponseVerificationSigner(agentID.String(), now)
	if err != nil {
		return observationuc.Signer{}, err
	}
	return observationuc.Signer{PrivateKey: signer.PrivateKey, Key: signer.Key}, nil
}

type outbox struct{ store *fleetclient.CredentialStore }

func (s outbox) LoadResponseVerificationReport(attemptKey string) (fleetagent.ResponseVerificationReport, bool, error) {
	return s.store.LoadResponseVerificationReport(attemptKey)
}

func (s outbox) SaveResponseVerificationReport(report fleetagent.ResponseVerificationReport) error {
	return s.store.SaveResponseVerificationReport(report)
}

func (s outbox) AcknowledgeResponseVerificationReport(attemptKey string) error {
	return s.store.AcknowledgeResponseVerificationReport(attemptKey)
}

type fleetTransport struct {
	api   API
	token string
}

func (t fleetTransport) RegisterSigningKey(ctx context.Context, key fleetagent.AgentSigningKey, proof string) error {
	return t.api.RegisterSigningKey(ctx, t.token, key, proof)
}

func (t fleetTransport) ShipResponseVerification(ctx context.Context, report fleetagent.ResponseVerificationReport) error {
	_, err := t.api.ShipResponseVerification(ctx, t.token, report)
	return err
}

type workReporter struct {
	api   API
	token string
}

func (w workReporter) Progress(ctx context.Context, id shared.ID, leaseID string) error {
	return w.api.Progress(ctx, w.token, id.String(), leaseID)
}

func (w workReporter) SubmitResult(ctx context.Context, id shared.ID, leaseID string, state workorder.State, reason string) error {
	return w.api.SubmitResult(ctx, w.token, id.String(), leaseID, string(state), reason)
}

var _ ports.Clock = idgen.SystemClock{}
