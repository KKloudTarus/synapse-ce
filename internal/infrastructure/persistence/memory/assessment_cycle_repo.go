package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
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
var _ ports.AssessmentCycleListRepository = (*AssessmentCycleRepository)(nil)
var _ ports.AssessmentCycleCompensationRepository = (*AssessmentCycleRepository)(nil)

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

func (r *AssessmentCycleRepository) DeleteCycle(_ context.Context, tenantID, cycleID shared.ID) error {
	tenantID = shared.TenantOrDefault(tenantID)
	r.mu.Lock()
	defer r.mu.Unlock()
	for assessmentID := range r.members[tenantID][cycleID] {
		delete(r.assessmentToCycle[tenantID], assessmentID)
	}
	delete(r.members[tenantID], cycleID)
	delete(r.cycles[tenantID], cycleID)
	return nil
}

func (r *AssessmentCycleRepository) DeleteMember(_ context.Context, tenantID, cycleID, assessmentID shared.ID) error {
	tenantID = shared.TenantOrDefault(tenantID)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.members[tenantID][cycleID], assessmentID)
	delete(r.assessmentToCycle[tenantID], assessmentID)
	return nil
}

func (r *AssessmentCycleRepository) ListCycles(_ context.Context, query ports.AssessmentCycleListQuery) ([]ports.AssessmentCycleListRecord, error) {
	tenantID := shared.TenantOrDefault(query.TenantID)
	if tenantID.IsZero() || query.Limit <= 0 {
		return nil, fmt.Errorf("%w: tenant and positive cycle list limit are required", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if query.MemberLimit <= 0 {
		query.MemberLimit = 10
	}
	records := make([]ports.AssessmentCycleListRecord, 0, len(r.cycles[tenantID]))
	for _, cycle := range r.cycles[tenantID] {
		if cycle.TenantID != tenantID || query.Status != "" && cycle.Status != query.Status || query.BoundaryKind != "" && cycle.BoundaryKind != query.BoundaryKind {
			continue
		}
		if !query.SelectedHeadID.IsZero() && cycle.SelectedHeadAssessmentID != query.SelectedHeadID {
			continue
		}
		if query.Search != "" {
			needle := strings.ToLower(query.Search)
			if !strings.Contains(strings.ToLower(cycle.Name), needle) && !strings.Contains(strings.ToLower(cycle.ID.String()), needle) &&
				!strings.Contains(strings.ToLower(cycle.RootAssessmentID.String()), needle) && !strings.Contains(strings.ToLower(cycle.SelectedHeadAssessmentID.String()), needle) {
				continue
			}
		}
		if query.AssessmentStatus != "" || query.ScanStaleness != "" {
			continue
		}
		if !query.AfterUpdatedAt.IsZero() && (cycle.UpdatedAt.After(query.AfterUpdatedAt) || cycle.UpdatedAt.Equal(query.AfterUpdatedAt) && cycle.ID >= query.AfterCycleID) {
			continue
		}
		members := make([]assessmentcycle.Member, 0)
		for _, member := range r.members[tenantID][cycle.ID] {
			members = append(members, *cloneMember(member))
		}
		if query.AssessmentType != "" {
			matched := false
			for _, member := range members {
				if member.AssessmentType == query.AssessmentType {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		sort.Slice(members, func(left, right int) bool {
			if members[left].RetestNumber == members[right].RetestNumber {
				return members[left].AssessmentID < members[right].AssessmentID
			}
			return members[left].RetestNumber < members[right].RetestNumber
		})
		latestID, latestNumber := shared.ID(""), -1
		activeCount := 0
		for _, member := range members {
			if member.IsArchived() {
				continue
			}
			activeCount++
			if member.RetestNumber > latestNumber || member.RetestNumber == latestNumber && member.AssessmentID > latestID {
				latestID, latestNumber = member.AssessmentID, member.RetestNumber
			}
		}
		records = append(records, ports.AssessmentCycleListRecord{
			Cycle: *cloneCycle(cycle), MemberCount: activeCount, ActiveBranchCount: len(assessmentcycle.DeriveBranchHeads(members)),
			LatestAssessmentID: latestID, LatestRetestNumber: latestNumber,
			Members:         append([]assessmentcycle.Member(nil), members[:min(len(members), query.MemberLimit)]...),
			MembersHaveMore: len(members) > query.MemberLimit,
		})
	}
	sort.Slice(records, func(left, right int) bool {
		if records[left].Cycle.UpdatedAt.Equal(records[right].Cycle.UpdatedAt) {
			return records[left].Cycle.ID > records[right].Cycle.ID
		}
		return records[left].Cycle.UpdatedAt.After(records[right].Cycle.UpdatedAt)
	})
	if len(records) > query.Limit {
		records = records[:query.Limit]
	}
	return records, nil
}

func (r *AssessmentCycleRepository) ListMigrationPendingAssessments(context.Context, ports.AssessmentCycleListQuery) ([]ports.AssessmentCycleMigrationPendingRecord, int, error) {
	return nil, 0, nil
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
