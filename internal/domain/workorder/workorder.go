// Package workorder is the epic-#405 fleet work order model: a unit of work addressed to a
// specific agent identity, authorised by an engagement, signed by the control plane, and driven
// through an explicit state machine. It is pure domain: it imports only shared and the stdlib.
//
// The signing itself lives outside the domain (a platform signer holds the key); the domain only
// defines the canonical, deterministic payload that is signed, so the authorising fields cannot
// drift between issue and verify.
package workorder

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// State is the lifecycle of a work order. Terminal states never transition again.
type State string

const (
	StateIssued    State = "issued"
	StateClaimed   State = "claimed"
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateExpired   State = "expired"
	StateCancelled State = "cancelled"
	StateRefused   State = "refused"
)

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	switch s {
	case StateIssued, StateClaimed, StateRunning, StateSucceeded, StateFailed,
		StateExpired, StateCancelled, StateRefused:
		return true
	default:
		return false
	}
}

// Terminal reports whether s is a final state.
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateExpired, StateCancelled, StateRefused:
		return true
	default:
		return false
	}
}

// allowedTransitions is the closed transition graph. Anything not listed is rejected.
var allowedTransitions = map[State]map[State]bool{
	StateIssued:  {StateClaimed: true, StateExpired: true, StateCancelled: true},
	StateClaimed: {StateRunning: true, StateRefused: true, StateExpired: true, StateCancelled: true},
	StateRunning: {StateSucceeded: true, StateFailed: true, StateCancelled: true},
}

// CanTransition reports whether from -> to is a legal transition.
func CanTransition(from, to State) bool {
	return allowedTransitions[from][to]
}

// WorkOrder is one addressed, signed, authorised unit of work.
type WorkOrder struct {
	ID              shared.ID
	TenantID        shared.ID
	AssetID         shared.ID
	AgentID         shared.ID // the addressed recipient; only this agent may claim it
	Capability      string    // e.g. scan.source, scan.host, detect.rules
	AuthorizationID shared.ID // the engagement/assessment that authorises the work
	IdempotencyKey  string
	NotAfter        time.Time // expiry; the order cannot be claimed after this
	TimeBucket      int64     // unix bucket for the in-flight uniqueness guard
	State           State
	RefuseReason    string // non-empty only when State == StateRefused
	Signature       string // control-plane signature over SigningPayload()
	Audit           shared.Audit
}

// New validates and constructs a work order in the issued state. Signature is set separately by
// the issuing service after signing SigningPayload().
func New(id, tenantID, assetID, agentID shared.ID, capability string, authorizationID shared.ID, idempotencyKey string, notAfter time.Time, timeBucket int64, now time.Time) (*WorkOrder, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: work order id is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: work order tenant id is required (empty tenant is DENY under RLS)", shared.ErrValidation)
	}
	if assetID.IsZero() {
		return nil, fmt.Errorf("%w: work order asset id is required", shared.ErrValidation)
	}
	if agentID.IsZero() {
		return nil, fmt.Errorf("%w: work order agent id is required (orders are addressed)", shared.ErrValidation)
	}
	capability = strings.TrimSpace(capability)
	if capability == "" {
		return nil, fmt.Errorf("%w: work order capability is required", shared.ErrValidation)
	}
	if authorizationID.IsZero() {
		return nil, fmt.Errorf("%w: work order authorization id is required", shared.ErrValidation)
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return nil, fmt.Errorf("%w: work order idempotency key is required", shared.ErrValidation)
	}
	if notAfter.IsZero() {
		return nil, fmt.Errorf("%w: work order expiry (not_after) is required", shared.ErrValidation)
	}
	return &WorkOrder{
		ID:              id,
		TenantID:        tenantID,
		AssetID:         assetID,
		AgentID:         agentID,
		Capability:      capability,
		AuthorizationID: authorizationID,
		IdempotencyKey:  idempotencyKey,
		NotAfter:        notAfter,
		TimeBucket:      timeBucket,
		State:           StateIssued,
		Audit:           shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}

// SigningPayload is the canonical, deterministic representation of the authorising fields that the
// control plane signs and the agent verifies. Order and separators are fixed so the signature is
// stable. It deliberately covers the identity, the capability, the authorising engagement and the
// expiry, so a tampered target, capability, authorization or expiry invalidates the signature.
func (w *WorkOrder) SigningPayload() string {
	return strings.Join([]string{
		w.ID.String(),
		w.TenantID.String(),
		w.AssetID.String(),
		w.AgentID.String(),
		w.Capability,
		w.AuthorizationID.String(),
		w.NotAfter.UTC().Format(time.RFC3339Nano),
	}, "\n")
}
