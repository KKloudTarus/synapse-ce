package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AssessmentCycleRepository persists tenant-scoped AssessmentCycle aggregates and their members.
type AssessmentCycleRepository interface {
	// CreateCycle persists a new AssessmentCycle. Fails with shared.ErrConflict if cycle ID already exists.
	CreateCycle(ctx context.Context, cycle *assessmentcycle.AssessmentCycle) error

	// GetCycle retrieves an AssessmentCycle by ID within tenantID. Returns shared.ErrNotFound if not found.
	GetCycle(ctx context.Context, tenantID, cycleID shared.ID) (*assessmentcycle.AssessmentCycle, error)

	// GetCycleByAssessment finds the AssessmentCycle containing assessmentID within tenantID.
	// Returns shared.ErrNotFound if the assessment is not part of any cycle.
	GetCycleByAssessment(ctx context.Context, tenantID, assessmentID shared.ID) (*assessmentcycle.AssessmentCycle, error)

	// UpdateCycleCAS updates a cycle aggregate if its current version matches expectedVersion.
	// Returns shared.ErrConflict on version mismatch.
	UpdateCycleCAS(ctx context.Context, cycle *assessmentcycle.AssessmentCycle, expectedVersion int64) error

	// CreateMember persists a new member record within a cycle. Fails with shared.ErrConflict
	// if the assessment already belongs to any cycle in the tenant.
	CreateMember(ctx context.Context, member *assessmentcycle.Member) error

	// GetMember retrieves a member by assessmentID within a cycle. Returns shared.ErrNotFound if not found.
	GetMember(ctx context.Context, tenantID, cycleID, assessmentID shared.ID) (*assessmentcycle.Member, error)

	// ListMembers returns all members belonging to cycleID within tenantID, sorted deterministically
	// by RetestNumber ASC, AssessmentID ASC.
	ListMembers(ctx context.Context, tenantID, cycleID shared.ID) ([]assessmentcycle.Member, error)

	// UpdateMemberCAS updates a member's predecessor or archived status if relationship_version matches expectedVersion.
	// Returns shared.ErrConflict on version mismatch.
	UpdateMemberCAS(ctx context.Context, member *assessmentcycle.Member, expectedVersion int64) error

	// LockCycleForUpdate acquires a row lock on the cycle aggregate within the active transaction
	// to serialize retest number allocation and selected-head advancement.
	LockCycleForUpdate(ctx context.Context, tenantID, cycleID shared.ID) (*assessmentcycle.AssessmentCycle, error)
}
