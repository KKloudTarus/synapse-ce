package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AssessmentCycleRepository is an in-memory implementation of ports.AssessmentCycleRepository.
type AssessmentCycleRepository struct {
	mu                sync.Mutex
	cycles            map[shared.ID]map[shared.ID]*assessmentcycle.AssessmentCycle
	members           map[shared.ID]map[shared.ID]map[shared.ID]*assessmentcycle.Member
	assessmentToCycle map[shared.ID]map[shared.ID]shared.ID
}

// NewAssessmentCycleRepository creates a new in-memory AssessmentCycleRepository.
func NewAssessmentCycleRepository() *AssessmentCycleRepository {
	return &AssessmentCycleRepository{
		cycles:            make(map[shared.ID]map[shared.ID]*assessmentcycle.AssessmentCycle),
		members:           make(map[shared.ID]map[shared.ID]map[shared.ID]*assessmentcycle.Member),
		assessmentToCycle: make(map[shared.ID]map[shared.ID]shared.ID),
	}
}

var _ ports.AssessmentCycleRepository = (*AssessmentCycleRepository)(nil)

func (r *AssessmentCycleRepository) CreateCycle(ctx context.Context, cycle *assessmentcycle.AssessmentCycle) error {
	if cycle == nil {
		return fmt.Errorf("%w: cycle is nil", shared.ErrValidation)
	}
	if err := cycle.Validate(); err != nil {
		return err
	}

	tenantID := shared.TenantOrDefault(cycle.TenantID)

	r.mu.Lock()
	defer r.mu.Unlock()

	tenantCycles := r.cycles[tenantID]
	if tenantCycles == nil {
		tenantCycles = make(map[shared.ID]*assessmentcycle.AssessmentCycle)
		r.cycles[tenantID] = tenantCycles
	}

	if _, exists := tenantCycles[cycle.ID]; exists {
		return fmt.Errorf("%w: cycle %q already exists in tenant %q", shared.ErrConflict, cycle.ID, tenantID)
	}

	tenantCycles[cycle.ID] = cloneCycle(cycle)
	return nil
}

func (r *AssessmentCycleRepository) GetCycle(ctx context.Context, tenantID, cycleID shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	cycle, exists := r.cycles[tenantID][cycleID]
	if !exists {
		return nil, fmt.Errorf("%w: cycle %q not found in tenant %q", shared.ErrNotFound, cycleID, tenantID)
	}

	return cloneCycle(cycle), nil
}

func (r *AssessmentCycleRepository) GetCycleByAssessment(ctx context.Context, tenantID, assessmentID shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || assessmentID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and assessment ids are required", shared.ErrValidation)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	cycleID, exists := r.assessmentToCycle[tenantID][assessmentID]
	if !exists {
		return nil, fmt.Errorf("%w: assessment %q does not belong to any cycle in tenant %q", shared.ErrNotFound, assessmentID, tenantID)
	}

	cycle, exists := r.cycles[tenantID][cycleID]
	if !exists {
		return nil, fmt.Errorf("%w: cycle %q not found for assessment %q", shared.ErrNotFound, cycleID, assessmentID)
	}

	return cloneCycle(cycle), nil
}

func (r *AssessmentCycleRepository) UpdateCycleCAS(ctx context.Context, cycle *assessmentcycle.AssessmentCycle, expectedVersion int64) error {
	if cycle == nil {
		return fmt.Errorf("%w: cycle is nil", shared.ErrValidation)
	}
	if err := cycle.Validate(); err != nil {
		return err
	}

	tenantID := shared.TenantOrDefault(cycle.TenantID)

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.cycles[tenantID][cycle.ID]
	if !exists {
		return fmt.Errorf("%w: cycle %q not found in tenant %q", shared.ErrNotFound, cycle.ID, tenantID)
	}

	if expectedVersion > 0 && existing.Version != expectedVersion {
		return fmt.Errorf("%w: cycle version mismatch (expected %d, found %d)", shared.ErrConflict, expectedVersion, existing.Version)
	}

	r.cycles[tenantID][cycle.ID] = cloneCycle(cycle)
	return nil
}

func (r *AssessmentCycleRepository) CreateMember(ctx context.Context, member *assessmentcycle.Member) error {
	if member == nil {
		return fmt.Errorf("%w: member is nil", shared.ErrValidation)
	}
	if err := member.Validate(); err != nil {
		return err
	}

	tenantID := shared.TenantOrDefault(member.TenantID)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Enforce global uniqueness: one Assessment in at most one Cycle
	tenantAssToCycle := r.assessmentToCycle[tenantID]
	if tenantAssToCycle == nil {
		tenantAssToCycle = make(map[shared.ID]shared.ID)
		r.assessmentToCycle[tenantID] = tenantAssToCycle
	}
	if existingCycleID, exists := tenantAssToCycle[member.AssessmentID]; exists {
		return fmt.Errorf("%w: assessment %q already belongs to cycle %q", shared.ErrConflict, member.AssessmentID, existingCycleID)
	}

	tenantMembers := r.members[tenantID]
	if tenantMembers == nil {
		tenantMembers = make(map[shared.ID]map[shared.ID]*assessmentcycle.Member)
		r.members[tenantID] = tenantMembers
	}
	cycleMembers := tenantMembers[member.CycleID]
	if cycleMembers == nil {
		cycleMembers = make(map[shared.ID]*assessmentcycle.Member)
		tenantMembers[member.CycleID] = cycleMembers
	}

	// Validate unique retest number and single root per cycle
	for _, m := range cycleMembers {
		if m.AssessmentType == assessmentcycle.AssessmentTypeInitial && member.AssessmentType == assessmentcycle.AssessmentTypeInitial {
			return fmt.Errorf("%w: cycle %q already has an initial root member", shared.ErrConflict, member.CycleID)
		}
		if m.RetestNumber == member.RetestNumber {
			return fmt.Errorf("%w: cycle %q already has member with retest number %d", shared.ErrConflict, member.CycleID, member.RetestNumber)
		}
	}

	cycleMembers[member.AssessmentID] = cloneMember(member)
	tenantAssToCycle[member.AssessmentID] = member.CycleID
	return nil
}

func (r *AssessmentCycleRepository) GetMember(ctx context.Context, tenantID, cycleID, assessmentID shared.ID) (*assessmentcycle.Member, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() || assessmentID.IsZero() {
		return nil, fmt.Errorf("%w: tenant, cycle, and assessment ids are required", shared.ErrValidation)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	member, exists := r.members[tenantID][cycleID][assessmentID]
	if !exists {
		return nil, fmt.Errorf("%w: member %q not found in cycle %q", shared.ErrNotFound, assessmentID, cycleID)
	}

	return cloneMember(member), nil
}

func (r *AssessmentCycleRepository) ListMembers(ctx context.Context, tenantID, cycleID shared.ID) ([]assessmentcycle.Member, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	cycleMembers := r.members[tenantID][cycleID]
	var out []assessmentcycle.Member
	for _, m := range cycleMembers {
		out = append(out, *cloneMember(m))
	}

	assessmentcycle.SortMembers(out)
	return out, nil
}

func (r *AssessmentCycleRepository) UpdateMemberCAS(ctx context.Context, member *assessmentcycle.Member, expectedVersion int64) error {
	if member == nil {
		return fmt.Errorf("%w: member is nil", shared.ErrValidation)
	}
	if err := member.Validate(); err != nil {
		return err
	}

	tenantID := shared.TenantOrDefault(member.TenantID)

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.members[tenantID][member.CycleID][member.AssessmentID]
	if !exists {
		return fmt.Errorf("%w: member %q not found in cycle %q", shared.ErrNotFound, member.AssessmentID, member.CycleID)
	}

	if expectedVersion > 0 && existing.RelationshipVersion != expectedVersion {
		return fmt.Errorf("%w: member relationship version mismatch (expected %d, found %d)", shared.ErrConflict, expectedVersion, existing.RelationshipVersion)
	}

	r.members[tenantID][member.CycleID][member.AssessmentID] = cloneMember(member)
	return nil
}

func (r *AssessmentCycleRepository) LockCycleForUpdate(ctx context.Context, tenantID, cycleID shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	return r.GetCycle(ctx, tenantID, cycleID)
}

func cloneCycle(c *assessmentcycle.AssessmentCycle) *assessmentcycle.AssessmentCycle {
	if c == nil {
		return nil
	}
	copy := *c
	return &copy
}

func cloneMember(m *assessmentcycle.Member) *assessmentcycle.Member {
	if m == nil {
		return nil
	}
	copy := *m
	if m.ArchivedAt != nil {
		t := *m.ArchivedAt
		copy.ArchivedAt = &t
	}
	return &copy
}
