package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentrelationship"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentRelationshipRepository struct {
	mu         sync.RWMutex
	candidates map[shared.ID]map[shared.ID]assessmentrelationship.Candidate
	inputs     map[shared.ID]map[string]shared.ID
	decisions  map[shared.ID]map[shared.ID]assessmentrelationship.Decision
	plans      map[shared.ID]map[shared.ID]assessmentrelationship.RepairPlan
	requests   map[shared.ID]map[string]assessmentrelationship.Decision
}

func NewAssessmentRelationshipRepository() *AssessmentRelationshipRepository {
	return &AssessmentRelationshipRepository{
		candidates: map[shared.ID]map[shared.ID]assessmentrelationship.Candidate{},
		inputs:     map[shared.ID]map[string]shared.ID{}, decisions: map[shared.ID]map[shared.ID]assessmentrelationship.Decision{},
		plans: map[shared.ID]map[shared.ID]assessmentrelationship.RepairPlan{}, requests: map[shared.ID]map[string]assessmentrelationship.Decision{},
	}
}

var _ ports.AssessmentRelationshipRepository = (*AssessmentRelationshipRepository)(nil)

func (repository *AssessmentRelationshipRepository) CreateCandidate(_ context.Context, candidate assessmentrelationship.Candidate) (assessmentrelationship.Record, bool, error) {
	candidate.TenantID = shared.TenantOrDefault(candidate.TenantID)
	if err := candidate.Validate(); err != nil {
		return assessmentrelationship.Record{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.ensureTenant(candidate.TenantID)
	if id, exists := repository.inputs[candidate.TenantID][candidate.InputHash]; exists {
		return repository.recordLocked(candidate.TenantID, id), false, nil
	}
	if _, exists := repository.candidates[candidate.TenantID][candidate.ID]; exists {
		return assessmentrelationship.Record{}, false, fmt.Errorf("%w: relationship candidate already exists", shared.ErrConflict)
	}
	repository.candidates[candidate.TenantID][candidate.ID] = cloneRelationshipCandidate(candidate)
	repository.inputs[candidate.TenantID][candidate.InputHash] = candidate.ID
	return repository.recordLocked(candidate.TenantID, candidate.ID), true, nil
}

func (repository *AssessmentRelationshipRepository) GetCandidate(_ context.Context, tenantID, candidateID shared.ID) (assessmentrelationship.Record, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if _, exists := repository.candidates[tenantID][candidateID]; !exists {
		return assessmentrelationship.Record{}, shared.ErrNotFound
	}
	return repository.recordLocked(tenantID, candidateID), nil
}

func (repository *AssessmentRelationshipRepository) ListCandidates(_ context.Context, tenantID shared.ID, filter ports.AssessmentRelationshipCandidateFilter) ([]assessmentrelationship.Record, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if filter.Limit < 1 || filter.Limit > 200 {
		return nil, fmt.Errorf("%w: relationship candidate page is invalid", shared.ErrValidation)
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	items := make([]assessmentrelationship.Candidate, 0, len(repository.candidates[tenantID]))
	for _, candidate := range repository.candidates[tenantID] {
		items = append(items, candidate)
	}
	sort.Slice(items, func(left, right int) bool {
		if !items[left].CreatedAt.Equal(items[right].CreatedAt) {
			return items[left].CreatedAt.After(items[right].CreatedAt)
		}
		return items[left].ID > items[right].ID
	})
	if len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	records := make([]assessmentrelationship.Record, 0, len(items))
	for _, candidate := range items {
		records = append(records, repository.recordLocked(tenantID, candidate.ID))
	}
	return records, nil
}

func (repository *AssessmentRelationshipRepository) DecideCandidateCAS(_ context.Context, decision assessmentrelationship.Decision, plan *assessmentrelationship.RepairPlan) (assessmentrelationship.Record, bool, error) {
	decision.TenantID = shared.TenantOrDefault(decision.TenantID)
	if err := decision.Validate(); err != nil {
		return assessmentrelationship.Record{}, false, err
	}
	if plan != nil {
		plan.TenantID = shared.TenantOrDefault(plan.TenantID)
		if err := plan.Validate(); err != nil {
			return assessmentrelationship.Record{}, false, err
		}
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID := decision.TenantID
	repository.ensureTenant(tenantID)
	requestKey := relationshipRequestKey(decision)
	if existing, exists := repository.requests[tenantID][requestKey]; exists {
		if existing.RequestHash != decision.RequestHash {
			return assessmentrelationship.Record{}, false, fmt.Errorf("%w: idempotency key was reused with different content", shared.ErrConflict)
		}
		return repository.recordLocked(tenantID, decision.CandidateID), true, nil
	}
	if _, exists := repository.candidates[tenantID][decision.CandidateID]; !exists {
		return assessmentrelationship.Record{}, false, shared.ErrNotFound
	}
	if _, exists := repository.decisions[tenantID][decision.CandidateID]; exists {
		return assessmentrelationship.Record{}, false, fmt.Errorf("%w: relationship candidate already has a decision", shared.ErrConflict)
	}
	if decision.ExpectedVersion != 1 {
		return assessmentrelationship.Record{}, false, fmt.Errorf("%w: relationship candidate version mismatch", shared.ErrConflict)
	}
	if plan != nil {
		if plan.TenantID != tenantID || plan.CandidateID != decision.CandidateID || plan.ID != decision.RepairPlanID {
			return assessmentrelationship.Record{}, false, fmt.Errorf("%w: relationship repair plan ownership is invalid", shared.ErrValidation)
		}
		repository.plans[tenantID][plan.ID] = cloneRelationshipPlan(*plan)
	}
	repository.decisions[tenantID][decision.CandidateID] = decision
	repository.requests[tenantID][requestKey] = decision
	return repository.recordLocked(tenantID, decision.CandidateID), false, nil
}

func (repository *AssessmentRelationshipRepository) ensureTenant(tenantID shared.ID) {
	if repository.candidates[tenantID] == nil {
		repository.candidates[tenantID] = map[shared.ID]assessmentrelationship.Candidate{}
		repository.inputs[tenantID] = map[string]shared.ID{}
		repository.decisions[tenantID] = map[shared.ID]assessmentrelationship.Decision{}
		repository.plans[tenantID] = map[shared.ID]assessmentrelationship.RepairPlan{}
		repository.requests[tenantID] = map[string]assessmentrelationship.Decision{}
	}
}

func (repository *AssessmentRelationshipRepository) recordLocked(tenantID, candidateID shared.ID) assessmentrelationship.Record {
	record := assessmentrelationship.Record{Candidate: cloneRelationshipCandidate(repository.candidates[tenantID][candidateID])}
	if decision, exists := repository.decisions[tenantID][candidateID]; exists {
		copyDecision := decision
		record.Decision = &copyDecision
		if !decision.RepairPlanID.IsZero() {
			plan := cloneRelationshipPlan(repository.plans[tenantID][decision.RepairPlanID])
			record.Plan = &plan
		}
	}
	return record
}

func relationshipRequestKey(decision assessmentrelationship.Decision) string {
	return strings.Join([]string{decision.CandidateID.String(), decision.Actor, decision.IdempotencyKey}, "\x00")
}

func cloneRelationshipCandidate(candidate assessmentrelationship.Candidate) assessmentrelationship.Candidate {
	candidate.Signals = append([]assessmentrelationship.Signal(nil), candidate.Signals...)
	return candidate
}

func cloneRelationshipPlan(plan assessmentrelationship.RepairPlan) assessmentrelationship.RepairPlan {
	plan.Body = append([]byte(nil), plan.Body...)
	return plan
}
