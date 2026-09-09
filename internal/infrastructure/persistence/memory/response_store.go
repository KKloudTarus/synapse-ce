package memory

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"sort"
	"sync"
	"time"

	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ResponseStore is the in-memory response-action store, tenant-bucketed so one tenant's actions are
// never visible to another. It mirrors the durable response journal and halt fence used by production.
type ResponseStore struct {
	mu         sync.Mutex
	byTenant   map[shared.ID]map[shared.ID]rdom.Record
	attempts   map[shared.ID]map[string]responsesaga.ResponseAttempt
	halt       map[shared.ID]int64
	halted     map[shared.ID]bool
	audits     map[shared.ID]map[string]ports.ResponseAuditIntent
	auditDone  map[shared.ID]map[string]bool
	dispatches map[shared.ID]map[int64]ports.ResponseHaltDispatch
}

var _ ports.ResponseAuditStore = (*ResponseStore)(nil)

// NewResponseStore constructs the store.
func NewResponseStore() *ResponseStore {
	return &ResponseStore{
		byTenant: map[shared.ID]map[shared.ID]rdom.Record{}, attempts: map[shared.ID]map[string]responsesaga.ResponseAttempt{},
		halt: map[shared.ID]int64{}, halted: map[shared.ID]bool{}, audits: map[shared.ID]map[string]ports.ResponseAuditIntent{},
		auditDone: map[shared.ID]map[string]bool{}, dispatches: map[shared.ID]map[int64]ports.ResponseHaltDispatch{},
	}
}

func (s *ResponseStore) CurrentHaltGeneration(ctx context.Context) (int64, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.halt[tenant], nil
}

// Get returns the record for an id in the ctx tenant.
func (s *ResponseStore) Get(ctx context.Context, id shared.ID) (rdom.Record, bool, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return rdom.Record{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byTenant[tenant][id]
	return cloneResponseRecord(r), ok, nil
}

// Put upserts a record under the authenticated tenant; a record claiming a different tenant is refused.
func (s *ResponseStore) Put(ctx context.Context, r rdom.Record) error {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return err
	}
	if r.TenantID != "" && r.TenantID != tenant {
		return shared.ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[tenant] == nil {
		s.byTenant[tenant] = map[shared.ID]rdom.Record{}
	}
	if existing, ok := s.byTenant[tenant][r.ID]; ok {
		if !sameMemoryResponseIdentity(existing, r) || existing.State != r.State {
			return shared.ErrConflict
		}
	}
	s.byTenant[tenant][r.ID] = cloneResponseRecord(r)
	return nil
}

func (s *ResponseStore) Transition(ctx context.Context, r rdom.Record, from rdom.State) (bool, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return false, err
	}
	if r.TenantID != tenant {
		return false, shared.ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, found := s.byTenant[tenant][r.ID]
	if !found {
		return false, shared.ErrNotFound
	}
	if !sameMemoryResponseIdentity(existing, r) {
		return false, shared.ErrConflict
	}
	if existing.State != from {
		return false, nil
	}
	s.byTenant[tenant][r.ID] = cloneResponseRecord(r)
	return true, nil
}

// ListByState returns the ctx tenant's records in the given state, deterministically ordered by id.
func (s *ResponseStore) ListByState(ctx context.Context, state rdom.State) ([]rdom.Record, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []rdom.Record
	for _, r := range s.byTenant[tenant] {
		if r.State == state {
			out = append(out, cloneResponseRecord(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *ResponseStore) StartAttempt(ctx context.Context, a responsesaga.ResponseAttempt) (responsesaga.ResponseAttempt, bool, error) {
	if err := a.Validate(); err != nil {
		return responsesaga.ResponseAttempt{}, false, err
	}
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return responsesaga.ResponseAttempt{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.HaltGeneration != s.halt[tenant] {
		return responsesaga.ResponseAttempt{}, false, fmt.Errorf("%w: %w", shared.ErrConflict, responsesaga.ErrStaleHaltGeneration)
	}
	if s.halted[tenant] {
		return responsesaga.ResponseAttempt{}, false, responsesaga.ErrHaltLatched
	}
	if s.attempts[tenant] == nil {
		s.attempts[tenant] = map[string]responsesaga.ResponseAttempt{}
	}
	if existing, ok := s.attempts[tenant][a.IdempotencyKey]; ok {
		if !sameMemoryAttemptIdentity(existing, a) {
			return responsesaga.ResponseAttempt{}, false, shared.ErrConflict
		}
		return existing, false, nil
	}
	s.attempts[tenant][a.IdempotencyKey] = a
	return a, true, nil
}

func (s *ResponseStore) ClaimAttempt(ctx context.Context, key string, from, to responsesaga.SagaState, at time.Time) (responsesaga.ResponseAttempt, bool, error) {
	if !responsesaga.CanTransition(from, to) {
		return responsesaga.ResponseAttempt{}, false, fmt.Errorf("%w: illegal response attempt claim", shared.ErrValidation)
	}
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return responsesaga.ResponseAttempt{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, found := s.attempts[tenant][key]
	if !found {
		return responsesaga.ResponseAttempt{}, false, shared.ErrNotFound
	}
	if a.State != from || !at.Before(a.DeadlineAt) {
		return a, false, nil
	}
	a.State = to
	s.attempts[tenant][key] = a
	return a, true, nil
}

func (s *ResponseStore) TransitionAttempt(ctx context.Context, a responsesaga.ResponseAttempt, from responsesaga.SagaState) (responsesaga.ResponseAttempt, bool, error) {
	return s.transitionAttempt(ctx, a, from)
}

func (s *ResponseStore) transitionAttempt(ctx context.Context, a responsesaga.ResponseAttempt, from responsesaga.SagaState) (responsesaga.ResponseAttempt, bool, error) {
	if err := a.Validate(); err != nil {
		return responsesaga.ResponseAttempt{}, false, err
	}
	if !responsesaga.CanTransition(from, a.State) {
		return responsesaga.ResponseAttempt{}, false, fmt.Errorf("%w: illegal response attempt transition", shared.ErrValidation)
	}
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return responsesaga.ResponseAttempt{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, found := s.attempts[tenant][a.IdempotencyKey]
	if !found {
		return responsesaga.ResponseAttempt{}, false, shared.ErrNotFound
	}
	if !sameMemoryAttemptIdentity(existing, a) {
		return responsesaga.ResponseAttempt{}, false, shared.ErrConflict
	}
	if existing.State != from {
		return existing, false, nil
	}
	s.attempts[tenant][a.IdempotencyKey] = a
	return a, true, nil
}

func (s *ResponseStore) GetAttempt(ctx context.Context, key string) (responsesaga.ResponseAttempt, bool, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return responsesaga.ResponseAttempt{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, found := s.attempts[tenant][key]
	return a, found, nil
}

func (s *ResponseStore) AttemptStillCurrent(ctx context.Context, key string, state responsesaga.SagaState, at time.Time) (bool, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, found := s.attempts[tenant][key]
	return found && a.State == state && at.Before(a.DeadlineAt) && a.HaltGeneration == s.halt[tenant] && !s.halted[tenant], nil
}

func (s *ResponseStore) ListAttemptsByState(ctx context.Context, states ...responsesaga.SagaState) ([]responsesaga.ResponseAttempt, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return nil, err
	}
	wanted := make(map[responsesaga.SagaState]bool, len(states))
	for _, state := range states {
		wanted[state] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []responsesaga.ResponseAttempt
	for _, attempt := range s.attempts[tenant] {
		if wanted[attempt.State] {
			out = append(out, attempt)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ActionID != out[j].ActionID {
			return out[i].ActionID < out[j].ActionID
		}
		if out[i].IsReversal != out[j].IsReversal {
			return !out[i].IsReversal
		}
		return out[i].Attempt < out[j].Attempt
	})
	return out, nil
}

func (s *ResponseStore) AdvanceHaltGenerationWithAudit(ctx context.Context, expected int64, intent ports.ResponseAuditIntent) (int64, ports.ResponseAuditIntent, ports.ResponseHaltDispatch, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, err
	}
	intent, err = intent.Normalize()
	if err != nil {
		return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, err
	}
	if intent.Entry.Target != tenant.String() {
		return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, shared.ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.halt[tenant] != expected {
		return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, shared.ErrConflict
	}
	committed, err := s.putAuditLocked(tenant, intent)
	if err != nil {
		return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, err
	}
	s.halt[tenant]++
	s.halted[tenant] = true
	dispatch := ports.ResponseHaltDispatch{TenantID: tenant, Generation: s.halt[tenant], CreatedAt: intent.Entry.At}
	if s.dispatches[tenant] == nil {
		s.dispatches[tenant] = map[int64]ports.ResponseHaltDispatch{}
	}
	s.dispatches[tenant][dispatch.Generation] = dispatch
	return dispatch.Generation, committed, dispatch, nil
}

func (s *ResponseStore) TransitionWithAudit(ctx context.Context, r rdom.Record, from rdom.State, intent ports.ResponseAuditIntent) (bool, ports.ResponseAuditIntent, error) {
	intent, err := intent.Normalize()
	if err != nil {
		return false, ports.ResponseAuditIntent{}, err
	}
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return false, ports.ResponseAuditIntent{}, err
	}
	if r.TenantID != tenant {
		return false, ports.ResponseAuditIntent{}, shared.ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, found := s.byTenant[tenant][r.ID]
	if !found {
		return false, ports.ResponseAuditIntent{}, shared.ErrNotFound
	}
	if !sameMemoryResponseIdentity(existing, r) {
		return false, ports.ResponseAuditIntent{}, shared.ErrConflict
	}
	if existing.State != from {
		return false, ports.ResponseAuditIntent{}, nil
	}
	committed, err := s.putAuditLocked(tenant, intent)
	if err != nil {
		return false, ports.ResponseAuditIntent{}, err
	}
	s.byTenant[tenant][r.ID] = cloneResponseRecord(r)
	return true, committed, nil
}

func (s *ResponseStore) TransitionAttemptWithAudit(ctx context.Context, a responsesaga.ResponseAttempt, from responsesaga.SagaState, intent ports.ResponseAuditIntent) (responsesaga.ResponseAttempt, bool, ports.ResponseAuditIntent, error) {
	if err := a.Validate(); err != nil {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, err
	}
	if !responsesaga.CanTransition(from, a.State) {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, fmt.Errorf("%w: illegal response attempt transition", shared.ErrValidation)
	}
	intent, err := intent.Normalize()
	if err != nil {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, err
	}
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, found := s.attempts[tenant][a.IdempotencyKey]
	if !found {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, shared.ErrNotFound
	}
	if !sameMemoryAttemptIdentity(existing, a) {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, shared.ErrConflict
	}
	if existing.State != from {
		return existing, false, ports.ResponseAuditIntent{}, nil
	}
	committed, err := s.putAuditLocked(tenant, intent)
	if err != nil {
		return responsesaga.ResponseAttempt{}, false, ports.ResponseAuditIntent{}, err
	}
	s.attempts[tenant][a.IdempotencyKey] = a
	return a, true, committed, nil
}

func (s *ResponseStore) EnqueueResponseAudit(ctx context.Context, intent ports.ResponseAuditIntent) (ports.ResponseAuditIntent, error) {
	intent, err := intent.Normalize()
	if err != nil {
		return ports.ResponseAuditIntent{}, err
	}
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return ports.ResponseAuditIntent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putAuditLocked(tenant, intent)
}

func (s *ResponseStore) putAuditLocked(tenant shared.ID, intent ports.ResponseAuditIntent) (ports.ResponseAuditIntent, error) {
	if s.audits[tenant] == nil {
		s.audits[tenant] = map[string]ports.ResponseAuditIntent{}
	}
	if existing, found := s.audits[tenant][intent.ID]; found {
		if !ports.SameResponseAuditIntent(existing, intent) {
			return ports.ResponseAuditIntent{}, shared.ErrConflict
		}
		return existing, nil
	}
	s.audits[tenant][intent.ID] = cloneResponseAuditIntent(intent)
	return intent, nil
}

func (s *ResponseStore) ListPendingResponseAudits(ctx context.Context) ([]ports.ResponseAuditIntent, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.ResponseAuditIntent
	for id, intent := range s.audits[tenant] {
		if !s.auditDone[tenant][id] {
			out = append(out, cloneResponseAuditIntent(intent))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Entry.At.Equal(out[j].Entry.At) {
			return out[i].Entry.At.Before(out[j].Entry.At)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *ResponseStore) AcknowledgeResponseAudit(ctx context.Context, id string) error {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.audits[tenant][id]; !found {
		return shared.ErrNotFound
	}
	if s.auditDone[tenant] == nil {
		s.auditDone[tenant] = map[string]bool{}
	}
	s.auditDone[tenant][id] = true
	return nil
}

func (s *ResponseStore) ListPendingResponseHaltDispatches(ctx context.Context) ([]ports.ResponseHaltDispatch, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.ResponseHaltDispatch
	for _, dispatch := range s.dispatches[tenant] {
		out = append(out, dispatch)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Generation < out[j].Generation })
	return out, nil
}

func (s *ResponseStore) AcknowledgeResponseHaltDispatch(ctx context.Context, generation int64) error {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.dispatches[tenant][generation]; !found {
		return shared.ErrNotFound
	}
	return nil
}

func cloneResponseRecord(r rdom.Record) rdom.Record {
	r.Action.Argv = append([]string(nil), r.Action.Argv...)
	r.Action.Reversal.Argv = append([]string(nil), r.Action.Reversal.Argv...)
	return r
}
func cloneResponseAuditIntent(i ports.ResponseAuditIntent) ports.ResponseAuditIntent {
	i.Entry.Metadata = maps.Clone(i.Entry.Metadata)
	return i
}
func sameMemoryResponseIdentity(a, b rdom.Record) bool {
	a.State, b.State = "", ""
	a.ApprovedBy, b.ApprovedBy = "", ""
	a.ApprovalEvidenceID, b.ApprovalEvidenceID = "", ""
	a.AppliedAt, b.AppliedAt = time.Time{}, time.Time{}
	a.UpdatedAt, b.UpdatedAt = time.Time{}, time.Time{}
	a.Verification, b.Verification = "", ""
	a.ReversalRequestedBy, b.ReversalRequestedBy = "", ""
	return reflect.DeepEqual(a, b)
}
func sameMemoryAttemptIdentity(a, b responsesaga.ResponseAttempt) bool {
	a.State, b.State = "", ""
	a.CommandOutcome, b.CommandOutcome = "", ""
	a.VerificationOutcome, b.VerificationOutcome = "", ""
	a.ObservedRadius, b.ObservedRadius = "", ""
	a.AffectedCount, b.AffectedCount = 0, 0
	a.AlreadyApplied, b.AlreadyApplied = false, false
	a.VerificationChallenge, b.VerificationChallenge = "", ""
	a.VerifierID, b.VerifierID = "", ""
	a.VerificationEvidenceID, b.VerificationEvidenceID = "", ""
	a.TerminalReason, b.TerminalReason = "", ""
	a.At, b.At = time.Time{}, time.Time{}
	a.DeadlineAt, b.DeadlineAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}

func requireResponseTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", shared.ErrValidation
}
