package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CorrelationStateStore is the tenant-isolated in-memory twin of the durable
// two-phase work store. Its mutex makes each checkpoint/cursor/staging change one critical section.
type CorrelationStateStore struct {
	mu     sync.Mutex
	states map[shared.ID]map[shared.ID]correlation.State
	ledger map[shared.ID]map[shared.ID]map[shared.ID]struct{}
	staged map[shared.ID]map[shared.ID]map[correlation.SourcePosition][]correlation.Signal
}

var _ ports.CorrelationStateStore = (*CorrelationStateStore)(nil)

func NewCorrelationStateStore() *CorrelationStateStore {
	return &CorrelationStateStore{states: map[shared.ID]map[shared.ID]correlation.State{}, ledger: map[shared.ID]map[shared.ID]map[shared.ID]struct{}{}, staged: map[shared.ID]map[shared.ID]map[correlation.SourcePosition][]correlation.Signal{}}
}

func requireCorrelationTenant(ctx context.Context) (shared.ID, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return "", fmt.Errorf("%w: correlation state operation requires a tenant in context", shared.ErrValidation)
	}
	return tenant, nil
}
func (s *CorrelationStateStore) current(tenant, engagement shared.ID) correlation.State {
	if s.states[tenant] == nil {
		s.states[tenant] = map[shared.ID]correlation.State{}
	}
	return cloneCorrelationState(s.states[tenant][engagement])
}
func (s *CorrelationStateStore) LoadCorrelationState(ctx context.Context, engagementID shared.ID, signalIDs []shared.ID, activeLimit int) (correlation.State, error) {
	tenant, err := requireCorrelationTenant(ctx)
	if err != nil {
		return correlation.State{}, err
	}
	if engagementID.IsZero() {
		return correlation.State{}, fmt.Errorf("%w: correlation state requires an engagement id", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.current(tenant, engagementID)
	if activeLimit > 0 && len(state.ActiveSessions) > activeLimit {
		return correlation.State{}, fmt.Errorf("%w: correlation active-session limit exceeded", shared.ErrSaturated)
	}
	state.KnownSignalIDs = map[shared.ID]struct{}{}
	for _, id := range signalIDs {
		if s.ledger[tenant] != nil && s.ledger[tenant][engagementID] != nil {
			if _, ok := s.ledger[tenant][engagementID][id]; ok {
				state.KnownSignalIDs[id] = struct{}{}
			}
		}
	}
	return state, nil
}
func (s *CorrelationStateStore) BeginCorrelationSnapshot(ctx context.Context, engagementID shared.ID, expected uint64, upper correlation.SourcePosition, asOf time.Time, digest string) (correlation.Checkpoint, error) {
	tenant, err := requireCorrelationTenant(ctx)
	if err != nil {
		return correlation.Checkpoint{}, err
	}
	if engagementID.IsZero() || upper.RecordedAt.IsZero() || upper.ID.IsZero() || asOf.IsZero() || digest == "" {
		return correlation.Checkpoint{}, fmt.Errorf("%w: invalid correlation snapshot", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.current(tenant, engagementID)
	if state.Checkpoint.Revision != expected || state.Checkpoint.Phase != "" {
		return correlation.Checkpoint{}, fmt.Errorf("%w: correlation snapshot changed", shared.ErrConflict)
	}
	state.Checkpoint.Revision++
	state.Checkpoint.Phase = correlation.PhaseSource
	state.Checkpoint.Snapshot = upper
	state.Checkpoint.RetentionAsOf = asOf.UTC()
	state.Checkpoint.PolicyDigest = digest
	state.Checkpoint.SourceCursor = correlation.SourcePosition{}
	state.Checkpoint.StagedCursor = correlation.SignalPosition{}
	s.states[tenant][engagementID] = state
	return state.Checkpoint, nil
}
func (s *CorrelationStateStore) StageCorrelationSignals(ctx context.Context, engagementID shared.ID, expected uint64, next correlation.Checkpoint, signals []correlation.Signal) error {
	tenant, err := requireCorrelationTenant(ctx)
	if err != nil {
		return err
	}
	if engagementID.IsZero() {
		return fmt.Errorf("%w: correlation state requires an engagement id", shared.ErrValidation)
	}
	for _, signal := range signals {
		if err := signal.Validate(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.current(tenant, engagementID)
	key := next.Snapshot
	existing := s.staged[tenant][engagementID][key]
	if state.Checkpoint == next { // Retried page: validate its immutable staged payload without mutating state.
		return validateStagedSignals(existing, signals, true)
	}
	if state.Checkpoint.Revision != expected || state.Checkpoint.Phase != correlation.PhaseSource {
		return fmt.Errorf("%w: stale correlation source checkpoint", shared.ErrConflict)
	}
	if err := validateStageTransition(state.Checkpoint, expected, next); err != nil {
		return err
	}
	if err := validateStagedSignals(existing, signals, false); err != nil {
		return err
	}
	if s.staged[tenant] == nil {
		s.staged[tenant] = map[shared.ID]map[correlation.SourcePosition][]correlation.Signal{}
	}
	if s.staged[tenant][engagementID] == nil {
		s.staged[tenant][engagementID] = map[correlation.SourcePosition][]correlation.Signal{}
	}
	byID := make(map[shared.ID]correlation.Signal, len(existing)+len(signals))
	for _, signal := range existing {
		byID[signal.ID] = signal
	}
	for _, signal := range signals {
		byID[signal.ID] = signal
	}
	existing = existing[:0]
	for _, signal := range byID {
		existing = append(existing, signal)
	}
	s.staged[tenant][engagementID][key] = existing
	state.Checkpoint = next
	s.states[tenant][engagementID] = state
	return nil
}

func validateStageTransition(current correlation.Checkpoint, expected uint64, next correlation.Checkpoint) error {
	if next.Revision != expected+1 || (next.Phase != correlation.PhaseSource && next.Phase != correlation.PhaseConsume) || next.Snapshot != current.Snapshot || !next.RetentionAsOf.Equal(current.RetentionAsOf) || next.PolicyDigest != current.PolicyDigest || next.Completed != current.Completed || next.MaxObservedAt != current.MaxObservedAt || next.Watermark != current.Watermark || next.StagedCursor != current.StagedCursor {
		return fmt.Errorf("%w: invalid correlation source transition", shared.ErrValidation)
	}
	if !validSourcePosition(next.SourceCursor) || !validSourcePosition(current.SourceCursor) || sourcePositionAfterState(next.SourceCursor, next.Snapshot) {
		return fmt.Errorf("%w: invalid correlation source cursor", shared.ErrValidation)
	}
	if next.Phase == correlation.PhaseSource && !sourcePositionAfterState(next.SourceCursor, current.SourceCursor) {
		return fmt.Errorf("%w: source correlation cursor did not advance", shared.ErrValidation)
	}
	if next.Phase == correlation.PhaseConsume && next.SourceCursor != current.SourceCursor && !sourcePositionAfterState(next.SourceCursor, current.SourceCursor) {
		return fmt.Errorf("%w: source correlation cursor regressed", shared.ErrValidation)
	}
	return nil
}

func validSourcePosition(position correlation.SourcePosition) bool {
	return position.RecordedAt.IsZero() == position.ID.IsZero()
}

func sourcePositionAfterState(left, right correlation.SourcePosition) bool {
	return left.RecordedAt.After(right.RecordedAt) || (left.RecordedAt.Equal(right.RecordedAt) && left.ID > right.ID)
}

func validateStagedSignals(existing, signals []correlation.Signal, strictRetry bool) error {
	byID := make(map[shared.ID]correlation.Signal, len(existing)+len(signals))
	for _, signal := range existing {
		byID[signal.ID] = signal
	}
	for _, signal := range signals {
		prior, exists := byID[signal.ID]
		if (!exists && strictRetry) || (exists && !correlation.SameSignal(prior, signal)) {
			return fmt.Errorf("%w: staged correlation signal %s conflicts", shared.ErrConflict, signal.ID)
		}
		byID[signal.ID] = signal
	}
	return nil
}
func (s *CorrelationStateStore) ListStagedCorrelationSignals(ctx context.Context, engagementID shared.ID, snapshot correlation.SourcePosition, after correlation.SignalPosition, limit int) ([]correlation.Signal, bool, error) {
	tenant, err := requireCorrelationTenant(ctx)
	if err != nil {
		return nil, false, err
	}
	if limit <= 0 {
		return nil, false, fmt.Errorf("%w: invalid correlation page limit", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := append([]correlation.Signal(nil), s.staged[tenant][engagementID][snapshot]...)
	sort.Slice(list, func(i, j int) bool {
		if !list[i].OccurredAt.Equal(list[j].OccurredAt) {
			return list[i].OccurredAt.Before(list[j].OccurredAt)
		}
		return list[i].ID < list[j].ID
	})
	start := 0
	for start < len(list) && (!after.OccurredAt.IsZero() && (!list[start].OccurredAt.After(after.OccurredAt) && (list[start].OccurredAt.Before(after.OccurredAt) || list[start].ID <= after.ID))) {
		start++
	}
	end := start + limit
	more := end < len(list)
	if end > len(list) {
		end = len(list)
	}
	return list[start:end], more, nil
}
func (s *CorrelationStateStore) CommitCorrelationConsume(ctx context.Context, engagementID shared.ID, expected uint64, next correlation.Checkpoint, added []correlation.Assignment, active []correlation.ActiveSession, snapshot correlation.SourcePosition, complete bool) error {
	tenant, err := requireCorrelationTenant(ctx)
	if err != nil {
		return err
	}
	if engagementID.IsZero() {
		return fmt.Errorf("%w: correlation state requires an engagement id", shared.ErrValidation)
	}
	if err := validateAssignments(added); err != nil {
		return err
	}
	if err := validateActiveSessions(active); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.current(tenant, engagementID)
	if err := validateConsumeTransition(state, expected, next, snapshot, complete); err != nil {
		return err
	}
	ledger := s.ledger[tenant][engagementID]
	for _, assignment := range added {
		if _, ok := ledger[assignment.SignalID]; ok {
			return fmt.Errorf("%w: assigned correlation signal", shared.ErrConflict)
		}
	}
	if s.ledger[tenant] == nil {
		s.ledger[tenant] = map[shared.ID]map[shared.ID]struct{}{}
	}
	if s.ledger[tenant][engagementID] == nil {
		s.ledger[tenant][engagementID] = map[shared.ID]struct{}{}
	}
	for _, assignment := range added {
		s.ledger[tenant][engagementID][assignment.SignalID] = struct{}{}
	}
	state.Checkpoint = next
	state.ActiveSessions = append([]correlation.ActiveSession(nil), active...)
	if complete {
		state.Checkpoint = finalizedCheckpoint(next, snapshot)
		delete(s.staged[tenant][engagementID], snapshot)
	}
	s.states[tenant][engagementID] = state
	return nil
}

func validateAssignments(added []correlation.Assignment) error {
	seen := make(map[shared.ID]struct{}, len(added))
	for _, assignment := range added {
		if err := assignment.ValidateForStore(); err != nil {
			return err
		}
		if _, duplicate := seen[assignment.SignalID]; duplicate {
			return fmt.Errorf("%w: duplicate correlation assignment", shared.ErrConflict)
		}
		seen[assignment.SignalID] = struct{}{}
	}
	return nil
}

func validateActiveSessions(active []correlation.ActiveSession) error {
	seen := make(map[shared.ID]struct{}, len(active))
	for _, session := range active {
		if err := session.ValidateForStore(); err != nil {
			return err
		}
		key := session.AssetID + "\x00" + session.EntityID + "\x00" + session.IncidentID
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%w: duplicate active correlation session", shared.ErrValidation)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateConsumeTransition(state correlation.State, expected uint64, next correlation.Checkpoint, snapshot correlation.SourcePosition, complete bool) error {
	current := state.Checkpoint
	if current.Revision != expected || current.Phase != correlation.PhaseConsume || current.Snapshot != snapshot {
		return fmt.Errorf("%w: stale correlation consume checkpoint", shared.ErrConflict)
	}
	if snapshot.RecordedAt.IsZero() || snapshot.ID.IsZero() || next.Revision != expected+1 {
		return fmt.Errorf("%w: invalid correlation consume transition", shared.ErrValidation)
	}
	if (!current.MaxObservedAt.IsZero() && next.MaxObservedAt.Before(current.MaxObservedAt)) || (!current.Watermark.IsZero() && next.Watermark.Before(current.Watermark)) {
		return fmt.Errorf("%w: correlation event-time checkpoint cannot move backward", shared.ErrValidation)
	}
	if next.Snapshot != current.Snapshot || !next.RetentionAsOf.Equal(current.RetentionAsOf) || next.PolicyDigest != current.PolicyDigest || next.SourceCursor != current.SourceCursor || next.Completed != current.Completed || (!complete && !validStagedAdvance(current.StagedCursor, next.StagedCursor)) || (complete && next.StagedCursor != current.StagedCursor && !validStagedAdvance(current.StagedCursor, next.StagedCursor)) {
		return fmt.Errorf("%w: invalid correlation consume transition", shared.ErrValidation)
	}
	if !complete && next.Phase != correlation.PhaseConsume {
		return fmt.Errorf("%w: invalid intermediate correlation consume transition", shared.ErrValidation)
	}
	if complete && next.Phase != "" {
		return fmt.Errorf("%w: invalid final correlation consume transition", shared.ErrValidation)
	}
	return nil
}

func validStagedAdvance(current, next correlation.SignalPosition) bool {
	if current.OccurredAt.IsZero() {
		return (next.OccurredAt.IsZero() && next.ID.IsZero()) || (!next.OccurredAt.IsZero() && !next.ID.IsZero())
	}
	return !next.OccurredAt.IsZero() && !next.ID.IsZero() && (next.OccurredAt.After(current.OccurredAt) || (next.OccurredAt.Equal(current.OccurredAt) && next.ID > current.ID))
}

func finalizedCheckpoint(next correlation.Checkpoint, snapshot correlation.SourcePosition) correlation.Checkpoint {
	next.Phase = ""
	next.Completed = snapshot
	next.Snapshot = correlation.SourcePosition{}
	next.RetentionAsOf = time.Time{}
	next.SourceCursor = correlation.SourcePosition{}
	next.StagedCursor = correlation.SignalPosition{}
	next.PolicyDigest = ""
	return next
}

func (s *CorrelationStateStore) advanceCorrelationState(ctx context.Context, engagementID shared.ID, expected uint64, next correlation.Checkpoint, added []correlation.Assignment, active []correlation.ActiveSession) error {
	tenant, err := requireCorrelationTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.current(tenant, engagementID)
	if state.Checkpoint.Revision != expected || next.Revision != expected+1 {
		return fmt.Errorf("%w: stale correlation checkpoint", shared.ErrConflict)
	}
	if (!state.Checkpoint.MaxObservedAt.IsZero() && next.MaxObservedAt.Before(state.Checkpoint.MaxObservedAt)) || (!state.Checkpoint.Watermark.IsZero() && next.Watermark.Before(state.Checkpoint.Watermark)) {
		return fmt.Errorf("%w: correlation event-time checkpoint cannot move backward", shared.ErrValidation)
	}
	if s.ledger[tenant] == nil {
		s.ledger[tenant] = map[shared.ID]map[shared.ID]struct{}{}
	}
	if s.ledger[tenant][engagementID] == nil {
		s.ledger[tenant][engagementID] = map[shared.ID]struct{}{}
	}
	for _, a := range added {
		if err := a.ValidateForStore(); err != nil {
			return err
		}
		if _, ok := s.ledger[tenant][engagementID][a.SignalID]; ok {
			return fmt.Errorf("%w: assigned correlation signal", shared.ErrConflict)
		}
	}
	for _, a := range added {
		s.ledger[tenant][engagementID][a.SignalID] = struct{}{}
	}
	state.Checkpoint = next
	state.ActiveSessions = append([]correlation.ActiveSession(nil), active...)
	s.states[tenant][engagementID] = state
	return nil
}

func cloneCorrelationState(state correlation.State) correlation.State {
	state.ActiveSessions = append([]correlation.ActiveSession(nil), state.ActiveSessions...)
	state.KnownSignalIDs = nil
	return state
}
