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
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	CapabilityResponseProcess = "response.process"
	CapabilityResponseHalt    = "response.halt"
	CapabilityResponseObserve = "response.observe"
	ResponsePriority          = 100
	ResponseHaltPriority      = 200
	ResponseObservePriority   = 150
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
	StateRunning: {StateSucceeded: true, StateFailed: true, StateExpired: true, StateCancelled: true},
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
	LeaseID         string
	LeaseUntil      time.Time
	TimeBucket      int64 // unix bucket for the in-flight uniqueness guard
	State           State
	RefuseReason    string // non-empty only when State == StateRefused
	Signature       string // control-plane signature over SigningPayload()
	Priority        int
	ResponseCommand *fleetagent.ResponseCommand
	ResponseHalt    *fleetagent.ResponseHaltCommand
	ResponseObserve *fleetagent.ResponseObservationRequest
	ResponseResult  *fleetagent.ResponseExecutionResult
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

// AttachResponseCommand binds the dedicated signed response payload to this addressed work order.
// Ordinary work orders retain their original wire/signature shape.
func (w *WorkOrder) AttachResponseCommand(command fleetagent.ResponseCommand) error {
	if w.Capability != CapabilityResponseProcess || w.State != StateIssued || w.Signature != "" || w.ResponseHalt != nil || w.ResponseObserve != nil {
		return fmt.Errorf("%w: response command can only attach to an unsigned issued response order", shared.ErrValidation)
	}
	if err := command.Validate(); err != nil {
		return err
	}
	if command.CommandID != w.ID || command.TenantID != w.TenantID || command.AssetID != w.AssetID || command.AgentID != w.AgentID ||
		command.EngagementID != w.AuthorizationID || command.AttemptKey != w.IdempotencyKey || command.NotAfter.After(w.NotAfter) {
		return fmt.Errorf("%w: response command is not bound to its addressed work order", shared.ErrForbidden)
	}
	cp := command
	cp.Action.Argv = append([]string(nil), command.Action.Argv...)
	cp.Action.Reversal.Argv = append([]string(nil), command.Action.Reversal.Argv...)
	w.ResponseCommand = &cp
	w.Priority = ResponsePriority
	return w.ValidateResponseBinding()
}

// AttachResponseHaltCommand binds a signed monotonic endpoint fence to a high-priority work order.
func (w *WorkOrder) AttachResponseHaltCommand(command fleetagent.ResponseHaltCommand) error {
	if w.Capability != CapabilityResponseHalt || w.State != StateIssued || w.Signature != "" || w.ResponseCommand != nil || w.ResponseObserve != nil || w.ResponseResult != nil {
		return fmt.Errorf("%w: response halt can only attach to an unsigned issued halt order", shared.ErrValidation)
	}
	if err := command.Validate(); err != nil {
		return err
	}
	if command.CommandID != w.ID || command.TenantID != w.TenantID || command.AssetID != w.AssetID ||
		command.AgentID != w.AgentID || command.AttemptKey != w.IdempotencyKey || command.NotAfter.After(w.NotAfter) {
		return fmt.Errorf("%w: response halt command is not bound to its addressed work order", shared.ErrForbidden)
	}
	cp := command
	w.ResponseHalt = &cp
	w.Priority = ResponseHaltPriority
	return w.ValidateResponseBinding()
}

// AttachResponseObservation binds a verdict-free observer request to an addressed work order.
func (w *WorkOrder) AttachResponseObservation(request fleetagent.ResponseObservationRequest) error {
	if w.Capability != CapabilityResponseObserve || w.State != StateIssued || w.Signature != "" ||
		w.ResponseCommand != nil || w.ResponseHalt != nil || w.ResponseResult != nil {
		return fmt.Errorf("%w: response observation can only attach to an unsigned issued observer order", shared.ErrValidation)
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if request.RequestID != w.ID || request.TenantID != w.TenantID || request.AssetID != w.AssetID ||
		request.ObserverAgentID != w.AgentID || request.EngagementID != w.AuthorizationID ||
		request.NotAfter.After(w.NotAfter) {
		return fmt.Errorf("%w: response observation is not bound to its addressed work order", shared.ErrForbidden)
	}
	cp := request
	w.ResponseObserve = &cp
	w.Priority = ResponseObservePriority
	return w.ValidateResponseBinding()
}

// ValidateResponseBinding revalidates the persisted response-command envelope after a storage round trip.
func (w *WorkOrder) ValidateResponseBinding() error {
	switch w.Capability {
	case CapabilityResponseProcess:
		if w.Priority != ResponsePriority || w.ResponseCommand == nil || w.ResponseHalt != nil || w.ResponseObserve != nil {
			return fmt.Errorf("%w: response work order has no high-priority command", shared.ErrValidation)
		}
	case CapabilityResponseHalt:
		if w.Priority != ResponseHaltPriority || w.ResponseHalt == nil || w.ResponseCommand != nil || w.ResponseObserve != nil || w.ResponseResult != nil {
			return fmt.Errorf("%w: response halt work order has no highest-priority halt command", shared.ErrValidation)
		}
		command := w.ResponseHalt
		if err := command.Validate(); err != nil {
			return err
		}
		if command.CommandID != w.ID || command.TenantID != w.TenantID || command.AssetID != w.AssetID ||
			command.AgentID != w.AgentID || command.AttemptKey != w.IdempotencyKey || command.NotAfter.After(w.NotAfter) {
			return fmt.Errorf("%w: persisted response halt command is not bound to its work order", shared.ErrForbidden)
		}
		return nil
	case CapabilityResponseObserve:
		if w.Priority != ResponseObservePriority || w.ResponseObserve == nil || w.ResponseCommand != nil || w.ResponseHalt != nil || w.ResponseResult != nil {
			return fmt.Errorf("%w: response observer work order has no high-priority observation request", shared.ErrValidation)
		}
		request := w.ResponseObserve
		if err := request.Validate(); err != nil {
			return err
		}
		if request.RequestID != w.ID || request.TenantID != w.TenantID || request.AssetID != w.AssetID ||
			request.ObserverAgentID != w.AgentID || request.EngagementID != w.AuthorizationID ||
			request.NotAfter.After(w.NotAfter) {
			return fmt.Errorf("%w: persisted response observation is not bound to its work order", shared.ErrForbidden)
		}
		return nil
	default:
		if w.Priority != 0 || w.ResponseCommand != nil || w.ResponseHalt != nil || w.ResponseObserve != nil || w.ResponseResult != nil {
			return fmt.Errorf("%w: ordinary work order carries response-only fields", shared.ErrValidation)
		}
		return nil
	}
	command := w.ResponseCommand
	if err := command.Validate(); err != nil {
		return err
	}
	if command.CommandID != w.ID || command.TenantID != w.TenantID || command.AssetID != w.AssetID ||
		command.AgentID != w.AgentID || command.EngagementID != w.AuthorizationID ||
		command.AttemptKey != w.IdempotencyKey || command.NotAfter.After(w.NotAfter) {
		return fmt.Errorf("%w: persisted response command is not bound to its work order", shared.ErrForbidden)
	}
	if w.ResponseResult == nil {
		if w.State == StateSucceeded || w.State == StateFailed {
			return fmt.Errorf("%w: terminal response work order has no execution result", shared.ErrValidation)
		}
		return nil
	}
	result := *w.ResponseResult
	if err := result.Validate(); err != nil {
		return err
	}
	wantState, err := responseTerminalState(result.State)
	if err != nil {
		return err
	}
	if result.AttemptKey != command.AttemptKey || result.CommandDigest != fleetagent.ResponseCommandDigest(*command) ||
		result.LeaseID == "" || result.LeaseID != w.LeaseID || w.State != wantState {
		return fmt.Errorf("%w: response execution result is not bound to its work order", shared.ErrForbidden)
	}
	return nil
}

// CompleteResponse atomically models the only valid succeeded/failed transition for response work.
// An exact terminal retry is a no-op; a changed retry conflicts rather than rewriting history.
func (w *WorkOrder) CompleteResponse(result fleetagent.ResponseExecutionResult, reason string, now time.Time) (bool, error) {
	if w.ResponseCommand == nil || w.Capability != CapabilityResponseProcess {
		return false, fmt.Errorf("%w: response completion requires a response work order", shared.ErrValidation)
	}
	if err := result.Validate(); err != nil {
		return false, err
	}
	wantState, err := responseTerminalState(result.State)
	if err != nil {
		return false, err
	}
	if result.AttemptKey != w.ResponseCommand.AttemptKey || result.CommandDigest != fleetagent.ResponseCommandDigest(*w.ResponseCommand) ||
		result.LeaseID == "" || result.LeaseID != w.LeaseID {
		return false, fmt.Errorf("%w: response execution result is not bound to the current work-order lease", shared.ErrForbidden)
	}
	if w.ResponseResult != nil {
		if w.State == wantState && w.RefuseReason == reason && fleetagent.SameResponseExecutionResult(*w.ResponseResult, result) {
			return false, nil
		}
		return false, fmt.Errorf("%w: response work order already has another terminal result", shared.ErrConflict)
	}
	if w.State != StateRunning || !CanTransition(w.State, wantState) {
		return false, fmt.Errorf("%w: response work order cannot complete from %s", shared.ErrConflict, w.State)
	}
	now = now.UTC()
	if !now.Before(w.NotAfter) || w.LeaseUntil.IsZero() || !now.Before(w.LeaseUntil) {
		return false, fmt.Errorf("%w: response work-order authorization or lease expired before terminal result admission", shared.ErrForbidden)
	}
	completedAt := result.CompletedAt.UTC()
	if completedAt.Before(w.ResponseCommand.IssuedAt) || !completedAt.Before(w.NotAfter) || !completedAt.Before(w.LeaseUntil) {
		return false, fmt.Errorf("%w: response execution completion time is outside its signed lease window", shared.ErrForbidden)
	}
	candidate := *w
	cp := result
	candidate.State = wantState
	candidate.RefuseReason = reason
	candidate.ResponseResult = &cp
	candidate.Audit.UpdatedAt = now
	if err := candidate.ValidateResponseBinding(); err != nil {
		return false, err
	}
	*w = candidate
	return true, nil
}

func responseTerminalState(state fleetagent.ResponseExecutionState) (State, error) {
	switch state {
	case fleetagent.ResponseExecutionApplied:
		return StateSucceeded, nil
	case fleetagent.ResponseExecutionOutcomeUnknown:
		return StateFailed, nil
	default:
		return "", fmt.Errorf("%w: response execution result is not terminal", shared.ErrValidation)
	}
}

// SigningPayload is the canonical, deterministic representation of the authorising fields that the
// control plane signs and the agent verifies. Order and separators are fixed so the signature is
// stable. It deliberately covers the identity, the capability, the authorising engagement and the
// expiry, so a tampered target, capability, authorization or expiry invalidates the signature.
func (w *WorkOrder) SigningPayload() string {
	parts := []string{
		w.ID.String(),
		w.TenantID.String(),
		w.AssetID.String(),
		w.AgentID.String(),
		w.Capability,
		w.AuthorizationID.String(),
		w.NotAfter.UTC().Format(time.RFC3339Nano),
	}
	if w.ResponseCommand != nil {
		parts = append(parts, CapabilityResponseProcess, strconv.Itoa(w.Priority), fleetagent.ResponseCommandDigest(*w.ResponseCommand))
	} else if w.ResponseHalt != nil {
		parts = append(parts, CapabilityResponseHalt, strconv.Itoa(w.Priority), fleetagent.ResponseHaltCommandDigest(*w.ResponseHalt))
	} else if w.ResponseObserve != nil {
		parts = append(parts, CapabilityResponseObserve, strconv.Itoa(w.Priority), fleetagent.ResponseObservationRequestDigest(*w.ResponseObserve))
	}
	return strings.Join(parts, "\n")
}

// SameRequest reports whether two orders represent the same idempotent issue request. Generated IDs,
// signatures, state and audit timestamps are intentionally excluded.
func SameRequest(left, right *WorkOrder) bool {
	if left == nil || right == nil || left.TenantID != right.TenantID || left.AssetID != right.AssetID ||
		left.AgentID != right.AgentID || left.Capability != right.Capability || left.AuthorizationID != right.AuthorizationID ||
		left.IdempotencyKey != right.IdempotencyKey || !left.NotAfter.Equal(right.NotAfter) || left.TimeBucket != right.TimeBucket ||
		left.Priority != right.Priority {
		return false
	}
	if left.ResponseCommand != nil || right.ResponseCommand != nil {
		return left.ResponseCommand != nil && right.ResponseCommand != nil &&
			fleetagent.ResponseCommandDigest(*left.ResponseCommand) == fleetagent.ResponseCommandDigest(*right.ResponseCommand) &&
			left.ResponseCommand.Signature == right.ResponseCommand.Signature
	}
	if left.ResponseHalt != nil || right.ResponseHalt != nil {
		return left.ResponseHalt != nil && right.ResponseHalt != nil &&
			fleetagent.ResponseHaltCommandDigest(*left.ResponseHalt) == fleetagent.ResponseHaltCommandDigest(*right.ResponseHalt) &&
			left.ResponseHalt.Signature == right.ResponseHalt.Signature
	}
	if left.ResponseObserve != nil || right.ResponseObserve != nil {
		return left.ResponseObserve != nil && right.ResponseObserve != nil &&
			fleetagent.ResponseObservationRequestDigest(*left.ResponseObserve) == fleetagent.ResponseObservationRequestDigest(*right.ResponseObserve)
	}
	return true
}
