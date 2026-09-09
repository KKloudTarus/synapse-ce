package ports

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ResponseAuditIntent is the exact immutable audit payload committed with a response mutation.
type ResponseAuditIntent struct {
	ID    string
	Entry AuditEntry
}

// ResponseHaltDispatch is the durable obligation to raise an executor's tenant-local fence.
// Replaying an older generation is safe because executors may only raise, never lower, their fence.
type ResponseHaltDispatch struct {
	TenantID   shared.ID
	Generation int64
	CreatedAt  time.Time
}

// Normalize canonicalizes an audit obligation before it enters either persistence adapter.
func (i ResponseAuditIntent) Normalize() (ResponseAuditIntent, error) {
	i.ID = strings.TrimSpace(i.ID)
	i.Entry.Actor = strings.TrimSpace(i.Entry.Actor)
	i.Entry.Action = strings.TrimSpace(i.Entry.Action)
	i.Entry.Target = strings.TrimSpace(i.Entry.Target)
	i.Entry.At = i.Entry.At.UTC().Truncate(time.Microsecond)
	if i.ID == "" || i.Entry.Actor == "" || i.Entry.Action == "" || i.Entry.Target == "" || i.Entry.At.IsZero() {
		return ResponseAuditIntent{}, fmt.Errorf("%w: response audit intention is incomplete", shared.ErrValidation)
	}
	if i.Entry.Hash != "" || i.Entry.PreviousHash != "" {
		return ResponseAuditIntent{}, fmt.Errorf("%w: response audit intention cannot precompute chain hashes", shared.ErrValidation)
	}
	if strings.TrimSpace(i.Entry.Metadata["idempotency_key"]) == "" || i.Entry.Metadata["idempotency_key"] != i.ID {
		return ResponseAuditIntent{}, fmt.Errorf("%w: response audit intention id must match its idempotency key", shared.ErrValidation)
	}
	i.Entry.Metadata = maps.Clone(i.Entry.Metadata)
	return i, nil
}

// SameResponseAuditIntent reports whether an existing obligation is an exact retry.
func SameResponseAuditIntent(left, right ResponseAuditIntent) bool {
	return left.ID == right.ID && left.Entry.Actor == right.Entry.Actor &&
		left.Entry.Action == right.Entry.Action && left.Entry.Target == right.Entry.Target &&
		left.Entry.At.Equal(right.Entry.At) && left.Entry.Hash == right.Entry.Hash &&
		left.Entry.PreviousHash == right.Entry.PreviousHash && maps.Equal(left.Entry.Metadata, right.Entry.Metadata)
}

// ResponseStore persists governed response actions (#425): their state (for idempotency and the
// kill-switch halt set) and the approval that authorized them. Tenant-scoped through the chokepoint.
type ResponseStore interface {
	// CurrentHaltGeneration reads the fence generation. In PostgreSQL this is read-only and
	// does not initialize a fence; only ResponseHaltWriter may manufacture one.
	CurrentHaltGeneration(ctx context.Context) (int64, error)
	// Get returns the record for an id in the ctx tenant.
	Get(ctx context.Context, id shared.ID) (response.Record, bool, error)
	// Put upserts a record (immutable id) under the authenticated tenant.
	Put(ctx context.Context, r response.Record) error
	// Transition atomically replaces a record only when its current state matches from. Immutable action
	// identity is preserved; transitioned=false means another replica won the state race.
	Transition(ctx context.Context, r response.Record, from response.State) (transitioned bool, err error)
	// ListByState returns the ctx tenant's records in a state (e.g. pending, for a kill-switch halt).
	ListByState(ctx context.Context, s response.State) ([]response.Record, error)
	// StartAttempt durably creates an execution journal entry before a side effect. A retry with the
	// same immutable identity returns the existing entry with created=false; a key collision fails.
	StartAttempt(ctx context.Context, a responsesaga.ResponseAttempt) (stored responsesaga.ResponseAttempt, created bool, err error)
	// ClaimAttempt atomically advances exactly one delivery from an expected state. Only claimed=true may
	// execute a side effect; observing an already-executing attempt is deliberately not a claim.
	ClaimAttempt(ctx context.Context, idempotencyKey string, from, to responsesaga.SagaState, at time.Time) (stored responsesaga.ResponseAttempt, claimed bool, err error)
	// TransitionAttempt atomically writes a state transition and its complete outcome/provenance payload.
	TransitionAttempt(ctx context.Context, a responsesaga.ResponseAttempt, from responsesaga.SagaState) (stored responsesaga.ResponseAttempt, transitioned bool, err error)
	// GetAttempt returns a journal entry by its deterministic idempotency key.
	GetAttempt(ctx context.Context, idempotencyKey string) (responsesaga.ResponseAttempt, bool, error)
	// AttemptStillCurrent atomically checks both attempt state and tenant halt generation immediately before
	// dispatch. Executors receive the same generation so a future remote agent can enforce the fence too.
	AttemptStillCurrent(ctx context.Context, idempotencyKey string, state responsesaga.SagaState, at time.Time) (bool, error)
	// ListAttemptsByState returns tenant-scoped attempts in any requested state. The kill switch uses this
	// to fence both apply and reversal work claimed by any service replica.
	ListAttemptsByState(ctx context.Context, states ...responsesaga.SagaState) ([]responsesaga.ResponseAttempt, error)
}

// ResponseHaltWriter is the deliberately small mutation capability for the response kill switch.
// Its PostgreSQL implementation uses a dedicated identity/pool; normal response repositories never
// receive database privileges to manufacture a halt fence or a halt-dispatch obligation.
type ResponseHaltWriter interface {
	CurrentHaltGeneration(ctx context.Context) (int64, error)
	AdvanceHaltGenerationWithAudit(ctx context.Context, expected int64, intent ResponseAuditIntent) (generation int64, committed ResponseAuditIntent, dispatch ResponseHaltDispatch, err error)
}

// ResponseAuditStore commits ordinary response mutations and their audit obligations. The halt writer
// remains a distinct capability even though memory mode may implement both interfaces in one object.
type ResponseAuditStore interface {
	ResponseStore
	// AdvanceHaltGenerationWithAudit remains here for in-memory compatibility. PostgreSQL's
	// ordinary store rejects it; governed composition installs a ResponseHaltWriter separately.
	AdvanceHaltGenerationWithAudit(ctx context.Context, expected int64, intent ResponseAuditIntent) (generation int64, committed ResponseAuditIntent, dispatch ResponseHaltDispatch, err error)
	TransitionWithAudit(ctx context.Context, r response.Record, from response.State, intent ResponseAuditIntent) (transitioned bool, committed ResponseAuditIntent, err error)
	TransitionAttemptWithAudit(ctx context.Context, a responsesaga.ResponseAttempt, from responsesaga.SagaState, intent ResponseAuditIntent) (stored responsesaga.ResponseAttempt, transitioned bool, committed ResponseAuditIntent, err error)
	EnqueueResponseAudit(ctx context.Context, intent ResponseAuditIntent) (ResponseAuditIntent, error)
	ListPendingResponseAudits(ctx context.Context) ([]ResponseAuditIntent, error)
	AcknowledgeResponseAudit(ctx context.Context, id string) error
	ListPendingResponseHaltDispatches(ctx context.Context) ([]ResponseHaltDispatch, error)
	AcknowledgeResponseHaltDispatch(ctx context.Context, generation int64) error
}
