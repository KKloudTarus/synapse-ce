package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type provenanceKey struct {
	engagement shared.ID
	detection  shared.ID
}

// DetectionProvenanceStore is a tenant-isolated in-memory current projection plus immutable history.
type DetectionProvenanceStore struct {
	mu          sync.Mutex
	current     map[shared.ID]map[provenanceKey]detectionprovenance.Current
	transitions map[shared.ID]map[provenanceKey][]detectionprovenance.Transition
}

var _ ports.DetectionProvenanceStore = (*DetectionProvenanceStore)(nil)

func NewDetectionProvenanceStore() *DetectionProvenanceStore {
	return &DetectionProvenanceStore{current: map[shared.ID]map[provenanceKey]detectionprovenance.Current{}, transitions: map[shared.ID]map[provenanceKey][]detectionprovenance.Transition{}}
}

func provenanceTenant(ctx context.Context) (shared.ID, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return "", fmt.Errorf("%w: detection provenance requires a tenant in context", shared.ErrValidation)
	}
	return tenant, nil
}

func (s *DetectionProvenanceStore) AdmitPending(ctx context.Context, current detectionprovenance.Current, received detectionprovenance.Transition) error {
	tenant, err := provenanceTenant(ctx)
	if err != nil {
		return err
	}
	if err := current.Validate(); err != nil {
		return err
	}
	if err := received.Validate(); err != nil {
		return err
	}
	if current.TenantID != tenant || received.TenantID != tenant || current.EngagementID != received.EngagementID ||
		current.DetectionID != received.DetectionID || current.Status != detectionprovenance.StatusPending ||
		received.Sequence != 1 || received.Kind != detectionprovenance.Received || received.Status != detectionprovenance.StatusPending {
		return fmt.Errorf("%w: invalid pending detection provenance admission", shared.ErrValidation)
	}
	key := provenanceKey{engagement: current.EngagementID, detection: current.DetectionID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current[tenant] == nil {
		s.current[tenant] = map[provenanceKey]detectionprovenance.Current{}
		s.transitions[tenant] = map[provenanceKey][]detectionprovenance.Transition{}
	}
	if existing, ok := s.current[tenant][key]; ok {
		history := s.transitions[tenant][key]
		if existing.TenantID == current.TenantID && existing.EngagementID == current.EngagementID && existing.DetectionID == current.DetectionID &&
			string(existing.PendingInput) == string(current.PendingInput) && len(history) > 0 {
			if err := detectionprovenance.VerifyChain(history); err != nil {
				return fmt.Errorf("verify detection provenance chain: %w", err)
			}
			candidate := received
			candidate.OccurredAt = history[0].OccurredAt
			if detectionprovenance.EquivalentTransition(history[0], candidate) {
				return nil
			}
		}
		return fmt.Errorf("%w: detection provenance identity is already admitted with different content", shared.ErrConflict)
	}
	current.PendingInput = append([]byte(nil), current.PendingInput...)
	received = detectionprovenance.SealTransition(cloneProvenanceTransition(received), "")
	s.current[tenant][key] = current
	s.transitions[tenant][key] = []detectionprovenance.Transition{received}
	return nil
}

func (s *DetectionProvenanceStore) AppendTransition(ctx context.Context, transition detectionprovenance.Transition) error {
	tenant, err := provenanceTenant(ctx)
	if err != nil {
		return err
	}
	if err := transition.Validate(); err != nil {
		return err
	}
	if transition.TenantID != tenant {
		return fmt.Errorf("%w: detection provenance transition tenant differs from context", shared.ErrForbidden)
	}
	key := provenanceKey{engagement: transition.EngagementID, detection: transition.DetectionID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current[tenant] == nil {
		s.current[tenant] = map[provenanceKey]detectionprovenance.Current{}
		s.transitions[tenant] = map[provenanceKey][]detectionprovenance.Transition{}
	}
	history := s.transitions[tenant][key]
	var current *detectionprovenance.Current
	if got, ok := s.current[tenant][key]; ok {
		current = &got
	}
	if current == nil {
		return fmt.Errorf("%w: detection provenance must be admitted before advancing", shared.ErrConflict)
	}
	if len(history) == 0 {
		return fmt.Errorf("%w: detection provenance current state has no transition history", shared.ErrConflict)
	}
	if err := detectionprovenance.VerifyChain(history); err != nil {
		return fmt.Errorf("verify detection provenance chain: %w", err)
	}
	transition.Sequence = uint64(len(history) + 1)
	transition = cloneProvenanceTransition(transition)
	for _, existing := range history {
		candidate := transition
		candidate.Sequence = existing.Sequence
		candidate.OccurredAt = existing.OccurredAt
		if detectionprovenance.EquivalentTransition(existing, candidate) {
			return nil
		}
	}
	previous := history[len(history)-1]
	previousKind := previous.Kind
	transition = detectionprovenance.SealTransition(transition, previous.Hash)
	next, err := detectionprovenance.Apply(current, previousKind, transition)
	if err != nil {
		return err
	}
	s.transitions[tenant][key] = append(history, transition)
	s.current[tenant][key] = next
	return nil
}

func (s *DetectionProvenanceStore) Current(ctx context.Context, engagementID, detectionID shared.ID) (detectionprovenance.Current, bool, error) {
	tenant, err := provenanceTenant(ctx)
	if err != nil {
		return detectionprovenance.Current{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.current[tenant][provenanceKey{engagement: engagementID, detection: detectionID}]
	value.PendingInput = append([]byte(nil), value.PendingInput...)
	return value, ok, nil
}

func (s *DetectionProvenanceStore) ListCurrent(ctx context.Context, engagementID shared.ID) ([]detectionprovenance.Current, error) {
	tenant, err := provenanceTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]detectionprovenance.Current, 0)
	for key, value := range s.current[tenant] {
		if key.engagement == engagementID {
			value.PendingInput = append([]byte(nil), value.PendingInput...)
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DetectionID < out[j].DetectionID })
	return out, nil
}

func (s *DetectionProvenanceStore) ListPending(ctx context.Context) ([]detectionprovenance.Current, error) {
	tenant, err := provenanceTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]detectionprovenance.Current, 0)
	for _, value := range s.current[tenant] {
		if value.Status != detectionprovenance.StatusPending {
			continue
		}
		value.PendingInput = append([]byte(nil), value.PendingInput...)
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EngagementID == out[j].EngagementID {
			return out[i].DetectionID < out[j].DetectionID
		}
		return out[i].EngagementID < out[j].EngagementID
	})
	return out, nil
}

func (s *DetectionProvenanceStore) ListTransitions(ctx context.Context, engagementID, detectionID shared.ID) ([]detectionprovenance.Transition, error) {
	tenant, err := provenanceTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	history := s.transitions[tenant][provenanceKey{engagement: engagementID, detection: detectionID}]
	out := make([]detectionprovenance.Transition, len(history))
	for i, transition := range history {
		out[i] = cloneProvenanceTransition(transition)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	if err := detectionprovenance.VerifyChain(out); err != nil {
		return nil, fmt.Errorf("verify detection provenance chain: %w", err)
	}
	return out, nil
}

func cloneProvenanceTransition(transition detectionprovenance.Transition) detectionprovenance.Transition {
	transition.TelemetryRefs = append([]fleetagent.TelemetryReference(nil), transition.TelemetryRefs...)
	return transition
}
