package assessmentcycle

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Status represents the lifecycle status of an Assessment Cycle.
type Status string

const (
	StatusOpen      Status = "open"
	StatusCompleted Status = "completed"
	StatusArchived  Status = "archived"
)

// Valid reports whether s is a recognized assessment cycle status.
func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusCompleted, StatusArchived:
		return true
	default:
		return false
	}
}

// CanTransitionTo reports whether status transition s -> to is permissible.
func (s Status) CanTransitionTo(to Status) bool {
	switch s {
	case StatusOpen:
		return to == StatusCompleted || to == StatusArchived
	case StatusCompleted:
		return to == StatusOpen || to == StatusArchived
	case StatusArchived:
		return false // terminal state
	default:
		return false
	}
}

// AssessmentCycle is the aggregate root representing a cohesive series of assessment
// runs (root assessment + retests) with a frozen asset/project boundary.
type AssessmentCycle struct {
	TenantID                 shared.ID
	ID                       shared.ID
	Name                     string
	BoundaryKind             BoundaryKind
	BusinessAssetID          shared.ID
	ProjectID                shared.ID
	Status                   Status
	RootAssessmentID         shared.ID
	SelectedHeadAssessmentID shared.ID
	NextRetestNumber         int
	Version                  int64
	CreatedAt                time.Time
	UpdatedAt                time.Time
	CreatedBy                string
	UpdatedBy                string
}

// NewAssessmentCycle constructs and validates a new AssessmentCycle aggregate in open status.
func NewAssessmentCycle(
	id, tenantID shared.ID,
	name string,
	kind BoundaryKind,
	businessAssetID, projectID shared.ID,
	rootAssessmentID shared.ID,
	actor string,
	now time.Time,
) (*AssessmentCycle, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: cycle id is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: cycle tenant id is required", shared.ErrValidation)
	}
	if rootAssessmentID.IsZero() {
		return nil, fmt.Errorf("%w: root assessment id is required", shared.ErrValidation)
	}

	name = strings.TrimSpace(name)
	nameLen := utf8.RuneCountInString(name)
	if nameLen == 0 || nameLen > 256 {
		return nil, fmt.Errorf("%w: cycle name must be between 1 and 256 characters", shared.ErrValidation)
	}

	if err := ValidateBoundaryEnforcement(kind, businessAssetID, projectID); err != nil {
		return nil, err
	}

	actor = strings.TrimSpace(actor)

	c := &AssessmentCycle{
		TenantID:                 tenantID,
		ID:                       id,
		Name:                     name,
		BoundaryKind:             kind,
		BusinessAssetID:          businessAssetID,
		ProjectID:                projectID,
		Status:                   StatusOpen,
		RootAssessmentID:         rootAssessmentID,
		SelectedHeadAssessmentID: rootAssessmentID,
		NextRetestNumber:         1,
		Version:                  1,
		CreatedAt:                now,
		UpdatedAt:                now,
		CreatedBy:                actor,
		UpdatedBy:                actor,
	}

	return c, c.Validate()
}

// Validate checks all domain invariants on the AssessmentCycle.
func (c *AssessmentCycle) Validate() error {
	if c.ID.IsZero() || c.TenantID.IsZero() || c.RootAssessmentID.IsZero() || c.SelectedHeadAssessmentID.IsZero() {
		return fmt.Errorf("%w: cycle id, tenant, root, and selected head are required", shared.ErrValidation)
	}
	nameLen := utf8.RuneCountInString(strings.TrimSpace(c.Name))
	if nameLen == 0 || nameLen > 256 {
		return fmt.Errorf("%w: cycle name must be between 1 and 256 characters", shared.ErrValidation)
	}
	if !c.Status.Valid() {
		return fmt.Errorf("%w: unknown cycle status %q", shared.ErrValidation, c.Status)
	}
	if err := ValidateBoundaryEnforcement(c.BoundaryKind, c.BusinessAssetID, c.ProjectID); err != nil {
		return err
	}
	if c.NextRetestNumber < 1 {
		return fmt.Errorf("%w: next retest number must be >= 1, got %d", shared.ErrValidation, c.NextRetestNumber)
	}
	if c.Version < 1 {
		return fmt.Errorf("%w: cycle version must be >= 1, got %d", shared.ErrValidation, c.Version)
	}
	return nil
}

// Transition advances the cycle status according to the lifecycle state machine with CAS checking.
func (c *AssessmentCycle) Transition(to Status, expectedVersion int64, actor string, now time.Time) error {
	if expectedVersion > 0 && expectedVersion != c.Version {
		return fmt.Errorf("%w: cycle version mismatch (expected %d, current %d)", shared.ErrConflict, expectedVersion, c.Version)
	}
	if !to.Valid() {
		return fmt.Errorf("%w: unknown cycle status %q", shared.ErrValidation, to)
	}
	if c.Status == to {
		return nil
	}
	if !c.Status.CanTransitionTo(to) {
		return fmt.Errorf("%w: cycle cannot transition from %s to %s", shared.ErrValidation, c.Status, to)
	}
	c.Status = to
	c.Version++
	c.UpdatedAt = now
	c.UpdatedBy = strings.TrimSpace(actor)
	return nil
}

// SelectHead explicitly changes the selected head to targetAssessmentID with CAS checking.
func (c *AssessmentCycle) SelectHead(targetAssessmentID shared.ID, expectedVersion int64, actor string, now time.Time) error {
	if c.Status != StatusOpen {
		return fmt.Errorf("%w: cannot select head on non-open cycle (status: %s)", shared.ErrValidation, c.Status)
	}
	if expectedVersion > 0 && expectedVersion != c.Version {
		return fmt.Errorf("%w: cycle version mismatch (expected %d, current %d)", shared.ErrConflict, expectedVersion, c.Version)
	}
	if targetAssessmentID.IsZero() {
		return fmt.Errorf("%w: target head assessment id is required", shared.ErrValidation)
	}
	if c.SelectedHeadAssessmentID == targetAssessmentID {
		return nil
	}
	c.SelectedHeadAssessmentID = targetAssessmentID
	c.Version++
	c.UpdatedAt = now
	c.UpdatedBy = strings.TrimSpace(actor)
	return nil
}

// AdvanceRetest increments the retest sequence and conditionally advances selected head.
func (c *AssessmentCycle) AdvanceRetest(newAssessmentID, predecessorID shared.ID, expectedVersion int64, actor string, now time.Time) (int, error) {
	if c.Status != StatusOpen {
		return 0, fmt.Errorf("%w: cannot add retest to non-open cycle (status: %s)", shared.ErrValidation, c.Status)
	}
	if expectedVersion > 0 && expectedVersion != c.Version {
		return 0, fmt.Errorf("%w: cycle version mismatch (expected %d, current %d)", shared.ErrConflict, expectedVersion, c.Version)
	}
	if newAssessmentID.IsZero() || predecessorID.IsZero() {
		return 0, fmt.Errorf("%w: new assessment id and predecessor id are required", shared.ErrValidation)
	}

	allocatedRetestNumber := c.NextRetestNumber
	c.NextRetestNumber++

	if predecessorID == c.SelectedHeadAssessmentID {
		c.SelectedHeadAssessmentID = newAssessmentID
	}
	c.Version++
	c.UpdatedAt = now
	c.UpdatedBy = strings.TrimSpace(actor)

	return allocatedRetestNumber, nil
}
