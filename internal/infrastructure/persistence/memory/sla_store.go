package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SLAStore is the development/test adapter for the complete SLA governance aggregate. It mirrors
// the PostgreSQL adapter's tenant checks, idempotency, immutable history, optimistic transitions,
// and preservation of human state during machine assessment refreshes.
type SLAStore struct {
	mu sync.RWMutex

	policies     map[string]sla.Policy
	activePolicy map[shared.ID]string
	assessments  map[string]sla.Assessment
	current      map[string]shared.ID
	lifecycles   map[string]sla.Lifecycle
	events       map[string][]sla.LifecycleEvent
}

func NewSLAStore() *SLAStore {
	return &SLAStore{
		policies: map[string]sla.Policy{}, activePolicy: map[shared.ID]string{},
		assessments: map[string]sla.Assessment{}, current: map[string]shared.ID{},
		lifecycles: map[string]sla.Lifecycle{}, events: map[string][]sla.LifecycleEvent{},
	}
}

var _ ports.SLAStore = (*SLAStore)(nil)

func (s *SLAStore) PutPolicy(ctx context.Context, policy sla.Policy, activate bool) (bool, error) {
	tenantID, err := slaMemoryTenant(ctx, policy.TenantID)
	if err != nil {
		return false, err
	}
	policy.TenantID = tenantID
	if err := policy.Validate(); err != nil {
		return false, err
	}
	key := slaPolicyKey(tenantID, policy.Config.Version)
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, exists := s.policies[key]
	if exists && existing.SHA256 != policy.SHA256 {
		return false, fmt.Errorf("%w: sla policy version already has different content", shared.ErrConflict)
	}
	if !exists {
		s.policies[key] = cloneSLAPolicy(policy)
	}
	if activate {
		s.activePolicy[tenantID] = policy.Config.Version
	}
	return !exists, nil
}

func (s *SLAStore) ActivePolicy(ctx context.Context, tenantID shared.ID) (sla.Policy, error) {
	tenantID, err := slaMemoryTenant(ctx, tenantID)
	if err != nil {
		return sla.Policy{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	version, ok := s.activePolicy[tenantID]
	if !ok {
		return sla.Policy{}, shared.ErrNotFound
	}
	policy, ok := s.policies[slaPolicyKey(tenantID, version)]
	if !ok {
		return sla.Policy{}, shared.ErrNotFound
	}
	return cloneSLAPolicy(policy), nil
}

func (s *SLAStore) PolicyHistory(ctx context.Context, tenantID shared.ID) ([]sla.Policy, error) {
	tenantID, err := slaMemoryTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	items := make([]sla.Policy, 0)
	for _, policy := range s.policies {
		if policy.TenantID == tenantID {
			items = append(items, cloneSLAPolicy(policy))
		}
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].Config.Version > items[j].Config.Version
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items, nil
}

func (s *SLAStore) UpsertAssessment(ctx context.Context, assessment sla.Assessment) (sla.AssessmentUpsertResult, error) {
	tenantID, err := slaMemoryTenant(ctx, assessment.TenantID)
	if err != nil {
		return sla.AssessmentUpsertResult{}, err
	}
	assessment.TenantID = tenantID
	if err := assessment.Validate(); err != nil {
		return sla.AssessmentUpsertResult{}, err
	}
	key := slaFindingKey(tenantID, assessment.EngagementID, assessment.FindingID)
	idKey := slaAssessmentKey(tenantID, assessment.ID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.assessments[idKey]; ok {
		return sla.AssessmentUpsertResult{Assessment: cloneSLAAssessment(existing)}, nil
	}
	if previousID, ok := s.current[key]; ok {
		previous := s.assessments[slaAssessmentKey(tenantID, previousID)]
		assessment, err = sla.ContinueAssessment(assessment, previous)
		if err != nil {
			return sla.AssessmentUpsertResult{}, err
		}
	}
	s.assessments[idKey] = cloneSLAAssessment(assessment)
	s.current[key] = assessment.ID
	state, exists := s.lifecycles[key]
	if !exists {
		state, err = sla.NewLifecycle(assessment, assessment.AssessedAt)
		if err != nil {
			return sla.AssessmentUpsertResult{}, err
		}
	} else {
		// Risk intelligence advances provenance only. Status, acceptance, human attribution,
		// timestamps, and version are deliberately untouched.
		state.AssessmentID = assessment.ID
	}
	s.lifecycles[key] = cloneSLALifecycle(state)
	return sla.AssessmentUpsertResult{Assessment: cloneSLAAssessment(assessment), Created: true}, nil
}

func (s *SLAStore) Current(ctx context.Context, tenantID, engagementID, findingID shared.ID) (sla.Current, error) {
	tenantID, err := slaMemoryTenant(ctx, tenantID)
	if err != nil {
		return sla.Current{}, err
	}
	key := slaFindingKey(tenantID, engagementID, findingID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	assessmentID, ok := s.current[key]
	if !ok {
		return sla.Current{}, shared.ErrNotFound
	}
	assessment, assessmentOK := s.assessments[slaAssessmentKey(tenantID, assessmentID)]
	state, stateOK := s.lifecycles[key]
	if !assessmentOK || !stateOK {
		return sla.Current{}, fmt.Errorf("sla current pointer is incomplete: %w", shared.ErrNotFound)
	}
	return sla.Current{Assessment: cloneSLAAssessment(assessment), Lifecycle: cloneSLALifecycle(state)}, nil
}

func (s *SLAStore) ListCurrent(ctx context.Context, tenantID, engagementID shared.ID) ([]sla.Current, error) {
	tenantID, err := slaMemoryTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	items := make([]sla.Current, 0)
	for key, assessmentID := range s.current {
		assessment, ok := s.assessments[slaAssessmentKey(tenantID, assessmentID)]
		if !ok || assessment.TenantID != tenantID || assessment.EngagementID != engagementID {
			continue
		}
		state, ok := s.lifecycles[key]
		if !ok {
			continue
		}
		items = append(items, sla.Current{Assessment: cloneSLAAssessment(assessment), Lifecycle: cloneSLALifecycle(state)})
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].Assessment.Result.RemediateBy.Equal(items[j].Assessment.Result.RemediateBy) {
			return items[i].Assessment.FindingID < items[j].Assessment.FindingID
		}
		return items[i].Assessment.Result.RemediateBy.Before(items[j].Assessment.Result.RemediateBy)
	})
	return items, nil
}

func (s *SLAStore) AssessmentHistory(ctx context.Context, tenantID, engagementID, findingID shared.ID) ([]sla.Assessment, error) {
	tenantID, err := slaMemoryTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	items := make([]sla.Assessment, 0)
	for _, assessment := range s.assessments {
		if assessment.TenantID == tenantID && assessment.EngagementID == engagementID && assessment.FindingID == findingID {
			items = append(items, cloneSLAAssessment(assessment))
		}
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].AssessedAt.Equal(items[j].AssessedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].AssessedAt.After(items[j].AssessedAt)
	})
	return items, nil
}

func (s *SLAStore) SaveTransition(ctx context.Context, next sla.Lifecycle, event sla.LifecycleEvent) error {
	tenantID, err := slaMemoryTenant(ctx, next.TenantID)
	if err != nil {
		return err
	}
	next.TenantID, event.TenantID = tenantID, tenantID
	if err := next.Validate(); err != nil {
		return err
	}
	if err := validateSLAEvent(next, event); err != nil {
		return err
	}
	key := slaFindingKey(tenantID, next.EngagementID, next.FindingID)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.lifecycles[key]
	if !ok {
		return shared.ErrNotFound
	}
	// A machine intelligence refresh deliberately leaves Version unchanged while advancing
	// AssessmentID. Compare both: otherwise a human decision made from a stale risk view could race
	// the refresh and move the lifecycle pointer back to the old assessment.
	if current.Version != event.BeforeVersion || next.Version != current.Version+1 ||
		current.AssessmentID != next.AssessmentID {
		return fmt.Errorf("sla lifecycle changed: %w", shared.ErrConflict)
	}
	for _, existing := range s.events[key] {
		if existing.ID == event.ID {
			return fmt.Errorf("sla lifecycle event already exists: %w", shared.ErrConflict)
		}
	}
	s.lifecycles[key] = cloneSLALifecycle(next)
	s.events[key] = append(s.events[key], cloneSLAEvent(event))
	return nil
}

func (s *SLAStore) LifecycleEvents(ctx context.Context, tenantID, engagementID, findingID shared.ID) ([]sla.LifecycleEvent, error) {
	tenantID, err := slaMemoryTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	stored := s.events[slaFindingKey(tenantID, engagementID, findingID)]
	items := make([]sla.LifecycleEvent, len(stored))
	for i := range stored {
		items[i] = cloneSLAEvent(stored[i])
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].At.Equal(items[j].At) {
			return items[i].ID < items[j].ID
		}
		return items[i].At.Before(items[j].At)
	})
	return items, nil
}

func slaMemoryTenant(ctx context.Context, requested shared.ID) (shared.ID, error) {
	bound, err := requiredTenant(ctx)
	if err != nil {
		return "", err
	}
	requested = shared.TenantOrDefault(requested)
	if requested != bound {
		return "", fmt.Errorf("%w: sla tenant does not match context", shared.ErrValidation)
	}
	return bound, nil
}

func validateSLAEvent(next sla.Lifecycle, event sla.LifecycleEvent) error {
	if event.ID.IsZero() || event.TenantID != next.TenantID || event.EngagementID != next.EngagementID ||
		event.FindingID != next.FindingID || event.AssessmentID != next.AssessmentID || event.To != next.Status ||
		event.AfterVersion != next.Version || event.BeforeVersion+1 != event.AfterVersion || event.At.IsZero() {
		return fmt.Errorf("%w: sla lifecycle event does not match next state", shared.ErrValidation)
	}
	return nil
}

func slaPolicyKey(tenantID shared.ID, version string) string {
	return tenantID.String() + "\x00" + version
}

func slaFindingKey(tenantID, engagementID, findingID shared.ID) string {
	return tenantID.String() + "\x00" + engagementID.String() + "\x00" + findingID.String()
}

func slaAssessmentKey(tenantID, assessmentID shared.ID) string {
	return tenantID.String() + "\x00" + assessmentID.String()
}

func cloneSLAPolicy(value sla.Policy) sla.Policy { return value }

func cloneSLAAssessment(value sla.Assessment) sla.Assessment {
	value.Result.Breakdown.Overrides = append([]string(nil), value.Result.Breakdown.Overrides...)
	return value
}

func cloneSLALifecycle(value sla.Lifecycle) sla.Lifecycle {
	if value.AcceptedAt != nil {
		copied := *value.AcceptedAt
		value.AcceptedAt = &copied
	}
	if value.AcceptanceExpiresAt != nil {
		copied := *value.AcceptanceExpiresAt
		value.AcceptanceExpiresAt = &copied
	}
	return value
}

func cloneSLAEvent(value sla.LifecycleEvent) sla.LifecycleEvent {
	if value.AcceptanceExpiresAt != nil {
		copied := *value.AcceptanceExpiresAt
		value.AcceptanceExpiresAt = &copied
	}
	return value
}
