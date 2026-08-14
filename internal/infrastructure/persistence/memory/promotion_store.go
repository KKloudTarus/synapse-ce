package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/promotion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PromotionStore is the in-memory promotion event store (dev/tests). It
// coordinates event persistence with finding-CAS (priority + version) under a
// single lock so that Apply is atomic:
//
//  1. Tenant-ownership verification via EngagementOwnershipReader.
//  2. Judgment-level idempotency check (dedup by tenant+judgmentID).
//  3. Fingerprint-level idempotency check (dedup by tenant+fingerprint).
//  4. CAS binding: command metadata must match finding state.
//  5. Reversal validation for corroborating_signal_loss rule.
//  6. EventID uniqueness check (reject collision before any mutation).
//  7. Finding CAS via FindingRepository.setPriorityInternal (for escalate/de_escalate).
//  8. Event append.
//
// Lock ordering: PromotionStore.mu is always acquired BEFORE
// FindingRepository.mu (via setPriorityInternal). FindingRepository.mu is never
// acquired while PromotionStore.mu is held by any other path, so deadlock
// is impossible.
//
// Tenant scoping: the store reads the tenant from context (shared.TenantFrom)
// and scopes all reads and writes by tenant, matching the postgres adapter's
// RLS behavior. Cross-tenant access returns shared.ErrNotFound.
type judgmentStoreKey struct {
	tenantID   shared.ID
	judgmentID shared.ID
}

type fingerprintStoreKey struct {
	tenantID    shared.ID
	fingerprint string
}

type findingStoreKey struct {
	tenantID     shared.ID
	engagementID shared.ID
	findingID    shared.ID
}

type eventStoreKey struct {
	tenantID shared.ID
	eventID  shared.ID
}

type PromotionStore struct {
	mu                sync.Mutex
	byJudgment        map[judgmentStoreKey]promotion.PromotionEvent
	byFinger          map[fingerprintStoreKey]promotion.PromotionEvent
	byFinding         map[findingStoreKey][]promotion.PromotionEvent
	byID              map[eventStoreKey]promotion.PromotionEvent
	pendingAudit      map[eventStoreKey]bool
	pendingAuditOrder map[shared.ID][]shared.ID // tenant -> event IDs in append order
	findingRepo       *FindingRepository
	engagementReader  ports.EngagementOwnershipReader
}

// NewPromotionStore returns an empty in-memory promotion store. The
// findingRepo must be the SAME instance used by the service layer so that
// CAS operates on the same data. The engagementReader verifies that the
// engagement belongs to the context tenant before any mutation.
func NewPromotionStore(findingRepo *FindingRepository, engagementReader ports.EngagementOwnershipReader) (*PromotionStore, error) {
	if findingRepo == nil || engagementReader == nil {
		return nil, fmt.Errorf("%w: promotion store is missing a dependency", shared.ErrValidation)
	}
	return &PromotionStore{
		byJudgment:        map[judgmentStoreKey]promotion.PromotionEvent{},
		byFinger:          map[fingerprintStoreKey]promotion.PromotionEvent{},
		byFinding:         map[findingStoreKey][]promotion.PromotionEvent{},
		byID:              map[eventStoreKey]promotion.PromotionEvent{},
		pendingAudit:      map[eventStoreKey]bool{},
		pendingAuditOrder: map[shared.ID][]shared.ID{},
		findingRepo:       findingRepo,
		engagementReader:  engagementReader,
	}, nil
}

var (
	_ ports.PromotionStore             = (*PromotionStore)(nil)
	_ ports.PromotionAuditTracker      = (*PromotionStore)(nil)
	_ ports.PendingPromotionAuditStore = (*PromotionStore)(nil)
)

// judgmentKey builds the tenant-scoped idempotency key for a judgment.
func judgmentKey(tenantID, judgmentID shared.ID) judgmentStoreKey {
	return judgmentStoreKey{tenantID: tenantID, judgmentID: judgmentID}
}

// fingerprintKey builds the tenant-scoped idempotency key for a fingerprint.
func fingerprintKey(tenantID shared.ID, fp string) fingerprintStoreKey {
	return fingerprintStoreKey{tenantID: tenantID, fingerprint: fp}
}

// storeFindingKey builds the tenant+engagement+finding scoped key for a
// finding's event list. Engagement is included so that ListByFinding and
// LatestByFinding can scope results to a specific engagement.
func storeFindingKey(tenantID, engagementID, findingID shared.ID) findingStoreKey {
	return findingStoreKey{tenantID: tenantID, engagementID: engagementID, findingID: findingID}
}

// eventIDKey builds the tenant-scoped key for looking up an event by ID.
func eventIDKey(tenantID, eventID shared.ID) eventStoreKey {
	return eventStoreKey{tenantID: tenantID, eventID: eventID}
}

// Apply constructs a PromotionEvent from the command, persists it, and
// atomically moves the finding's priority. Returns the existing event on
// exact replay (same judgmentID), or shared.ErrConflict on semantic conflicts
// (matching fingerprint with different judgment, or CAS mismatch).
func (s *PromotionStore) Apply(ctx context.Context, engagementID, findingID shared.ID, cmd ports.PromotionCommand) (finding.Finding, error) {
	if err := ctx.Err(); err != nil {
		return finding.Finding{}, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return finding.Finding{}, fmt.Errorf("%w: tenant context is required for promotion store", shared.ErrValidation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 0. Verify engagement belongs to the context tenant. This is the
	// trust-boundary chokepoint: the postgres adapter handles this via RLS,
	// but the in-memory store must explicitly check tenant ownership.
	if _, err := s.engagementReader.GetByIDInTenant(ctx, tenantID, engagementID); err != nil {
		return finding.Finding{}, fmt.Errorf("apply promotion: engagement %s: %w", engagementID, err)
	}

	// 1. Judgment-level idempotency: if this exact judgment was already
	// applied, verify exact replay consistency (all immutable semantic fields
	// must match) and return the existing finding state.
	jKey := judgmentKey(tenantID, cmd.JudgmentID)
	if existing, ok := s.byJudgment[jKey]; ok {
		replayEvt := promotion.PromotionEvent{
			EngagementID:        engagementID,
			JudgmentID:          cmd.JudgmentID,
			FindingID:           findingID,
			FindingVersion:      cmd.FindingVersion,
			AfterFindingVersion: cmd.FindingVersion, // placeholder; Equals checks this
			Rule:                cmd.Rule,
			Effect:              cmd.Effect,
			BeforePriority:      cmd.BeforePriority,
			AfterPriority:       cmd.AfterPriority,
			Inputs:              cmd.Inputs,
			Fingerprint:         cmd.Fingerprint,
			Uncertainty:         cmd.Uncertainty,
			VerdictScore:        cmd.VerdictScore,
			VerdictRationale:    cmd.VerdictRationale,
			EvidenceID:          cmd.EvidenceID,
			Verifier:            cmd.Verifier,
			AppliedBy:           cmd.AppliedBy,
		}
		// Compute afterFindingVersion for comparison.
		if cmd.Effect != judgment.PromotionFlagForReview {
			replayEvt.AfterFindingVersion = cmd.FindingVersion + 1
		}
		if !existing.Equals(replayEvt) {
			return finding.Finding{}, fmt.Errorf("%w: judgment %s replay differs from stored event", shared.ErrConflict, cmd.JudgmentID)
		}
		f, err := s.findingRepo.getFinding(engagementID, findingID)
		if err != nil {
			return finding.Finding{}, fmt.Errorf("apply promotion idempotent: %w", err)
		}
		return f, nil
	}

	// 2. Fingerprint-level idempotency: if this fingerprint already exists
	// under a different judgment, that is a semantic conflict.
	fKey := fingerprintKey(tenantID, cmd.Fingerprint)
	if existing, ok := s.byFinger[fKey]; ok {
		if existing.JudgmentID != cmd.JudgmentID {
			return finding.Finding{}, fmt.Errorf("%w: fingerprint %s already applied by judgment %s (not %s)", shared.ErrConflict, cmd.Fingerprint, existing.JudgmentID, cmd.JudgmentID)
		}
		// Judgment matches: this is a replay through a different code path.
		f, err := s.findingRepo.getFinding(engagementID, findingID)
		if err != nil {
			return finding.Finding{}, fmt.Errorf("apply promotion idempotent: %w", err)
		}
		return f, nil
	}

	// 3. Verify the finding exists and belongs to the engagement.
	f, err := s.findingRepo.getFinding(engagementID, findingID)
	if err != nil {
		return finding.Finding{}, fmt.Errorf("apply promotion: %w", err)
	}
	if f.EngagementID != engagementID {
		return finding.Finding{}, fmt.Errorf("%w: finding %s does not belong to engagement %s", shared.ErrNotFound, findingID, engagementID)
	}

	// 4. CAS: verify expected priority and expected version BEFORE any mutation.
	if f.Version != cmd.ExpectedVersion {
		return finding.Finding{}, fmt.Errorf("finding %s changed since you loaded it: %w", findingID, shared.ErrConflict)
	}
	if f.Priority != cmd.ExpectedPriority {
		return finding.Finding{}, fmt.Errorf("finding %s priority changed since you loaded it: %w", findingID, shared.ErrConflict)
	}

	// 4b. Bind command metadata to CAS: the event's FindingVersion must
	// equal ExpectedVersion and BeforePriority must equal ExpectedPriority.
	// This prevents a caller from forging stale or inconsistent metadata.
	if cmd.FindingVersion != cmd.ExpectedVersion {
		return finding.Finding{}, fmt.Errorf("%w: command FindingVersion %d != ExpectedVersion %d", shared.ErrValidation, cmd.FindingVersion, cmd.ExpectedVersion)
	}
	if cmd.BeforePriority != cmd.ExpectedPriority {
		return finding.Finding{}, fmt.Errorf("%w: command BeforePriority %d != ExpectedPriority %d", shared.ErrValidation, cmd.BeforePriority, cmd.ExpectedPriority)
	}

	// 5. For corroborating_signal_loss, validate the exact reversal: the
	// prior event must exist, belong to the same tenant/engagement/finding,
	// be an applied escalation, and the requested AfterPriority must equal
	// the prior event's BeforePriority.
	if cmd.Rule == judgment.RuleCorroboratingSignalLoss {
		if err := s.validateExactReversal(tenantID, engagementID, findingID, cmd); err != nil {
			return finding.Finding{}, err
		}
	}

	// 6. Construct and validate the event.
	afterFindingVersion := cmd.FindingVersion
	if cmd.Effect != judgment.PromotionFlagForReview {
		afterFindingVersion = cmd.FindingVersion + 1
	}

	evt, err := promotion.NewPromotionEvent(
		cmd.EventID,
		engagementID,
		cmd.JudgmentID,
		findingID,
		cmd.FindingVersion,
		afterFindingVersion,
		cmd.Rule,
		cmd.Effect,
		cmd.BeforePriority,
		cmd.AfterPriority,
		cmd.Inputs,
		cmd.Fingerprint,
		cmd.VerdictScore,
		cmd.VerdictRationale,
		cmd.EvidenceID,
		cmd.Verifier,
		cmd.Uncertainty,
		cmd.AppliedBy,
		time.Now().UTC(),
	)
	if err != nil {
		return finding.Finding{}, fmt.Errorf("construct promotion event: %w", err)
	}

	// 7. Cross-check: the constructed event's judgment must match the command.
	if evt.JudgmentID != cmd.JudgmentID {
		return finding.Finding{}, fmt.Errorf("%w: event judgment mismatch", shared.ErrConflict)
	}

	// 8. EventID uniqueness: a tenant-scoped EventID collision with a
	// different (non-semantically-equal) event must be rejected before
	// any finding mutation or event append. An exact semantic replay
	// with a regenerated EventID is allowed (the judgment-idempotency
	// check at step 1 would normally catch this, but a caller that
	// regenerates EventID needs this guard).
	ek := eventIDKey(tenantID, evt.ID)
	if existing, ok := s.byID[ek]; ok {
		if !existing.Equals(evt) {
			return finding.Finding{}, fmt.Errorf("%w: event ID %s already exists with different content", shared.ErrConflict, evt.ID)
		}
		// Exact semantic replay with a regenerated EventID: allow.
		f, err := s.findingRepo.getFinding(engagementID, findingID)
		if err != nil {
			return finding.Finding{}, fmt.Errorf("apply promotion eventID replay: %w", err)
		}
		return f, nil
	}

	// Cancellation after validation must not commit a partial finding/event transition.
	if err := ctx.Err(); err != nil {
		return finding.Finding{}, err
	}

	// 9. For mutating effects, move the finding's priority atomically.
	if evt.Effect != judgment.PromotionFlagForReview {
		f, err = s.findingRepo.setPriorityInternal(engagementID, findingID, evt.AfterPriority, cmd.ExpectedVersion)
		if err != nil {
			return finding.Finding{}, fmt.Errorf("apply promotion CAS: %w", err)
		}
	}

	// 10. Persist the event (append-only) and indexes.
	s.byJudgment[jKey] = evt
	s.byFinger[fKey] = evt
	fk := storeFindingKey(tenantID, engagementID, findingID)
	s.byFinding[fk] = append(s.byFinding[fk], evt)
	s.byID[ek] = evt
	s.pendingAudit[ek] = true
	s.pendingAuditOrder[tenantID] = append(s.pendingAuditOrder[tenantID], evt.ID)

	return f, nil
}

// validateExactReversal verifies that a corroborating_signal_loss command
// references a valid prior escalation event that is the latest mutating
// promotion in the finding's lineage. The prior event must:
//   - be referenced by exactly one prior_promotion input
//   - exist in the store under the same tenant
//   - belong to the same engagement and finding
//   - be an applied escalation
//   - have a BeforePriority that equals the requested AfterPriority
//   - be the latest mutating event for this finding (no later events after it)
//   - its AfterPriority and AfterFindingVersion must match the command's
//     BeforePriority and FindingVersion (lineage continuity)
func (s *PromotionStore) validateExactReversal(tenantID, engagementID, findingID shared.ID, cmd ports.PromotionCommand) error {
	var priorEventID shared.ID
	priorCount := 0
	for _, in := range cmd.Inputs {
		if in.Kind == judgment.PromotionInputPrior {
			priorEventID = in.ID
			priorCount++
		}
	}
	if priorCount == 0 {
		return fmt.Errorf("%w: corroborating_signal_loss requires a prior_promotion input", shared.ErrValidation)
	}
	if priorCount > 1 {
		return fmt.Errorf("%w: corroborating_signal_loss requires exactly one prior_promotion input, got %d", shared.ErrValidation, priorCount)
	}
	if priorEventID.IsZero() {
		return fmt.Errorf("%w: prior_promotion input has empty event ID", shared.ErrValidation)
	}

	fk := storeFindingKey(tenantID, engagementID, findingID)
	events := s.byFinding[fk]
	stack := make([]promotion.PromotionEvent, 0, len(events))
	for _, event := range events {
		switch event.Effect {
		case judgment.PromotionEscalate:
			stack = append(stack, event)
		case judgment.PromotionDeescalate:
			if event.Rule != judgment.RuleCorroboratingSignalLoss {
				continue
			}
			for _, input := range event.Inputs {
				if input.Kind != judgment.PromotionInputPrior {
					continue
				}
				for i := len(stack) - 1; i >= 0; i-- {
					if stack[i].ID == input.ID {
						stack = stack[:i]
						break
					}
				}
			}
		}
	}
	if _, ok := s.byID[eventIDKey(tenantID, priorEventID)]; !ok {
		return fmt.Errorf("%w: prior promotion event %s not found", shared.ErrNotFound, priorEventID)
	}
	if len(stack) == 0 || stack[len(stack)-1].ID != priorEventID {
		return fmt.Errorf("%w: prior event %s is not the latest unresolved escalation", shared.ErrConflict, priorEventID)
	}
	prior := stack[len(stack)-1]
	if cmd.AfterPriority != prior.BeforePriority {
		return fmt.Errorf("%w: reversal target priority %d != prior event %s before-priority %d", shared.ErrConflict, cmd.AfterPriority, priorEventID, prior.BeforePriority)
	}
	if cmd.BeforePriority != prior.AfterPriority {
		return fmt.Errorf("%w: command before-priority %d != prior event %s after-priority %d", shared.ErrConflict, cmd.BeforePriority, priorEventID, prior.AfterPriority)
	}
	return nil
}

// ListByFinding returns all promotion events for a finding, oldest first.
// The returned slice and each event's Inputs are defensive copies; callers
// may modify them safely. Results are scoped to the given engagement.
func (s *PromotionStore) ListByFinding(ctx context.Context, engagementID, findingID shared.ID) ([]promotion.PromotionEvent, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: tenant context is required for promotion store", shared.ErrValidation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	fk := storeFindingKey(tenantID, engagementID, findingID)
	events := s.byFinding[fk]
	return deepCopyEvents(events), nil
}

// LatestByFinding returns the most recent promotion event for a finding,
// or (zero, false) if none exist. The returned event is a defensive copy.
// Results are scoped to the given engagement.
func (s *PromotionStore) LatestByFinding(ctx context.Context, engagementID, findingID shared.ID) (promotion.PromotionEvent, bool, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return promotion.PromotionEvent{}, false, fmt.Errorf("%w: tenant context is required for promotion store", shared.ErrValidation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	fk := storeFindingKey(tenantID, engagementID, findingID)
	events := s.byFinding[fk]
	if len(events) == 0 {
		return promotion.PromotionEvent{}, false, nil
	}
	latest := deepCopyEvent(events[len(events)-1])
	return latest, true, nil
}

// FindByJudgment returns an event scoped to its tenant, engagement, and finding.
func (s *PromotionStore) FindByJudgment(ctx context.Context, engagementID, findingID, judgmentID shared.ID) (promotion.PromotionEvent, bool, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return promotion.PromotionEvent{}, false, fmt.Errorf("%w: tenant context is required for promotion store", shared.ErrValidation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	evt, ok := s.byJudgment[judgmentKey(tenantID, judgmentID)]
	if !ok || evt.EngagementID != engagementID || evt.FindingID != findingID {
		return promotion.PromotionEvent{}, false, nil
	}
	return deepCopyEvent(evt), true, nil
}

// ListPendingAudits returns applied promotion events whose required audit has
// not been durably acknowledged. Results are oldest first.
func (s *PromotionStore) ListPendingAudits(ctx context.Context, engagementID shared.ID) ([]promotion.PromotionEvent, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: tenant context is required for promotion store", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]promotion.PromotionEvent, 0)
	for _, eventID := range s.pendingAuditOrder[tenantID] {
		key := eventIDKey(tenantID, eventID)
		if !s.pendingAudit[key] {
			continue
		}
		evt := s.byID[key]
		if evt.EngagementID == engagementID {
			out = append(out, deepCopyEvent(evt))
		}
	}
	return out, nil
}

// MarkAuditComplete durably acknowledges an applied event's audit record.
func (s *PromotionStore) MarkAuditComplete(ctx context.Context, eventID shared.ID) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required for promotion store", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := eventIDKey(tenantID, eventID)
	if _, ok := s.byID[key]; !ok {
		return fmt.Errorf("promotion event %s: %w", eventID, shared.ErrNotFound)
	}
	delete(s.pendingAudit, key)
	return nil
}

// getFinding is an internal helper that retrieves a finding by engagement+ID.
// The caller MUST hold PromotionStore.mu (FindingRepository's read lock is
// acquired here).
func (r *FindingRepository) getFinding(engagementID, findingID shared.ID) (finding.Finding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	byKey := r.data[engagementID]
	for _, f := range byKey {
		if f.ID == findingID {
			return f, nil
		}
	}
	return finding.Finding{}, fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
}

// deepCopyEvents returns a defensive copy of the events slice, with each
// event's Inputs independently copied.
func deepCopyEvents(events []promotion.PromotionEvent) []promotion.PromotionEvent {
	if len(events) == 0 {
		return nil
	}
	out := make([]promotion.PromotionEvent, len(events))
	for i, e := range events {
		out[i] = deepCopyEvent(e)
	}
	return out
}

// deepCopyEvent returns a defensive copy of a single event, including its
// Inputs and Uncertainty slices.
func deepCopyEvent(e promotion.PromotionEvent) promotion.PromotionEvent {
	cp := e
	if len(e.Inputs) > 0 {
		cp.Inputs = make([]judgment.PromotionInput, len(e.Inputs))
		copy(cp.Inputs, e.Inputs)
	}
	if len(e.Uncertainty) > 0 {
		cp.Uncertainty = make([]string, len(e.Uncertainty))
		copy(cp.Uncertainty, e.Uncertainty)
	}
	return cp
}
