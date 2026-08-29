package assessmentcycle

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AssessmentType indicates the nature of an Assessment's membership in a cycle.
type AssessmentType string

const (
	AssessmentTypeInitial AssessmentType = "initial"
	AssessmentTypeRetest  AssessmentType = "retest"
)

// Valid reports whether t is a recognized assessment type.
func (t AssessmentType) Valid() bool {
	switch t {
	case AssessmentTypeInitial, AssessmentTypeRetest:
		return true
	default:
		return false
	}
}

// Member represents a single Assessment associated with an AssessmentCycle.
type Member struct {
	TenantID                shared.ID
	CycleID                 shared.ID
	AssessmentID            shared.ID
	AssessmentType          AssessmentType
	PredecessorAssessmentID shared.ID
	RetestNumber            int
	RelationshipVersion     int64
	CreatedAt               time.Time
	CreatedBy               string
	ArchivedAt              *time.Time
}

// NewInitialMember creates the root member for an AssessmentCycle.
func NewInitialMember(tenantID, cycleID, assessmentID shared.ID, actor string, now time.Time) (*Member, error) {
	if tenantID.IsZero() || cycleID.IsZero() || assessmentID.IsZero() {
		return nil, fmt.Errorf("%w: tenant, cycle, and assessment ids are required for root member", shared.ErrValidation)
	}
	m := &Member{
		TenantID:                tenantID,
		CycleID:                 cycleID,
		AssessmentID:            assessmentID,
		AssessmentType:          AssessmentTypeInitial,
		PredecessorAssessmentID: "",
		RetestNumber:            0,
		RelationshipVersion:     1,
		CreatedAt:               now,
		CreatedBy:               strings.TrimSpace(actor),
		ArchivedAt:              nil,
	}
	return m, m.Validate()
}

// NewRetestMember creates a re-test member in an AssessmentCycle.
func NewRetestMember(
	tenantID, cycleID, assessmentID, predecessorID shared.ID,
	retestNumber int,
	actor string,
	now time.Time,
) (*Member, error) {
	if tenantID.IsZero() || cycleID.IsZero() || assessmentID.IsZero() {
		return nil, fmt.Errorf("%w: tenant, cycle, and assessment ids are required for retest member", shared.ErrValidation)
	}
	if predecessorID.IsZero() {
		return nil, fmt.Errorf("%w: retest member requires a predecessor assessment id", shared.ErrValidation)
	}
	if predecessorID == assessmentID {
		return nil, fmt.Errorf("%w: member cannot be its own predecessor", shared.ErrValidation)
	}
	if retestNumber <= 0 {
		return nil, fmt.Errorf("%w: retest number must be positive, got %d", shared.ErrValidation, retestNumber)
	}

	m := &Member{
		TenantID:                tenantID,
		CycleID:                 cycleID,
		AssessmentID:            assessmentID,
		AssessmentType:          AssessmentTypeRetest,
		PredecessorAssessmentID: predecessorID,
		RetestNumber:            retestNumber,
		RelationshipVersion:     1,
		CreatedAt:               now,
		CreatedBy:               strings.TrimSpace(actor),
		ArchivedAt:              nil,
	}
	return m, m.Validate()
}

// Validate checks domain invariants for a Member.
func (m *Member) Validate() error {
	if m.TenantID.IsZero() || m.CycleID.IsZero() || m.AssessmentID.IsZero() {
		return fmt.Errorf("%w: member tenant, cycle, and assessment ids are required", shared.ErrValidation)
	}
	if !m.AssessmentType.Valid() {
		return fmt.Errorf("%w: unknown assessment type %q", shared.ErrValidation, m.AssessmentType)
	}
	if m.RelationshipVersion < 1 {
		return fmt.Errorf("%w: member relationship version must be >= 1, got %d", shared.ErrValidation, m.RelationshipVersion)
	}

	if m.AssessmentType == AssessmentTypeInitial {
		if !m.PredecessorAssessmentID.IsZero() {
			return fmt.Errorf("%w: initial root member must not have a predecessor", shared.ErrValidation)
		}
		if m.RetestNumber != 0 {
			return fmt.Errorf("%w: initial root member must have retest number 0, got %d", shared.ErrValidation, m.RetestNumber)
		}
		if m.ArchivedAt != nil {
			return fmt.Errorf("%w: initial root member cannot be archived", shared.ErrValidation)
		}
	} else {
		if m.PredecessorAssessmentID.IsZero() {
			return fmt.Errorf("%w: retest member must have a predecessor", shared.ErrValidation)
		}
		if m.PredecessorAssessmentID == m.AssessmentID {
			return fmt.Errorf("%w: member cannot be its own predecessor", shared.ErrValidation)
		}
		if m.RetestNumber <= 0 {
			return fmt.Errorf("%w: retest member must have retest number > 0, got %d", shared.ErrValidation, m.RetestNumber)
		}
	}
	return nil
}

// IsRoot reports whether m is the initial root member.
func (m *Member) IsRoot() bool {
	return m.AssessmentType == AssessmentTypeInitial && m.RetestNumber == 0 && m.PredecessorAssessmentID.IsZero()
}

// IsArchived reports whether m is archived.
func (m *Member) IsArchived() bool {
	return m.ArchivedAt != nil
}

// Archive soft-deletes the member with CAS validation. Root members cannot be archived.
func (m *Member) Archive(expectedVersion int64, now time.Time) error {
	if m.IsRoot() {
		return fmt.Errorf("%w: root member cannot be archived", shared.ErrValidation)
	}
	if m.IsArchived() {
		return fmt.Errorf("%w: member is already archived", shared.ErrConflict)
	}
	if expectedVersion > 0 && expectedVersion != m.RelationshipVersion {
		return fmt.Errorf("%w: member relationship version mismatch (expected %d, current %d)", shared.ErrConflict, expectedVersion, m.RelationshipVersion)
	}
	m.ArchivedAt = &now
	m.RelationshipVersion++
	return nil
}

// Reparent updates the member's predecessor with CAS validation. Root members cannot be reparented.
func (m *Member) Reparent(newPredecessorID shared.ID, expectedVersion int64) error {
	if m.IsRoot() {
		return fmt.Errorf("%w: root member cannot be reparented", shared.ErrValidation)
	}
	if m.IsArchived() {
		return fmt.Errorf("%w: cannot reparent archived member", shared.ErrValidation)
	}
	if newPredecessorID.IsZero() {
		return fmt.Errorf("%w: new predecessor id is required", shared.ErrValidation)
	}
	if newPredecessorID == m.AssessmentID {
		return fmt.Errorf("%w: member cannot be its own predecessor", shared.ErrValidation)
	}
	if expectedVersion > 0 && expectedVersion != m.RelationshipVersion {
		return fmt.Errorf("%w: member relationship version mismatch (expected %d, current %d)", shared.ErrConflict, expectedVersion, m.RelationshipVersion)
	}
	m.PredecessorAssessmentID = newPredecessorID
	m.RelationshipVersion++
	return nil
}

// DeriveBranchHeads returns all non-archived members that have no active (non-archived) children.
// Results are deterministically sorted by RetestNumber ASC, AssessmentID ASC.
func DeriveBranchHeads(members []Member) []Member {
	hasActiveChild := make(map[shared.ID]bool)
	var activeMembers []Member

	for _, m := range members {
		if !m.IsArchived() {
			activeMembers = append(activeMembers, m)
			if !m.PredecessorAssessmentID.IsZero() {
				hasActiveChild[m.PredecessorAssessmentID] = true
			}
		}
	}

	var branchHeads []Member
	for _, m := range activeMembers {
		if !hasActiveChild[m.AssessmentID] {
			branchHeads = append(branchHeads, m)
		}
	}

	SortMembers(branchHeads)
	return branchHeads
}

// DeriveAncestors returns the ancestor chain of assessmentID, ordered from immediate predecessor to root.
func DeriveAncestors(members []Member, assessmentID shared.ID) ([]Member, error) {
	byID := make(map[shared.ID]Member, len(members))
	for _, m := range members {
		byID[m.AssessmentID] = m
	}

	target, exists := byID[assessmentID]
	if !exists {
		return nil, fmt.Errorf("%w: member %q not found", shared.ErrNotFound, assessmentID)
	}

	var ancestors []Member
	visited := make(map[shared.ID]bool)
	curr := target

	for !curr.PredecessorAssessmentID.IsZero() {
		if visited[curr.AssessmentID] {
			return nil, fmt.Errorf("%w: cycle detected in member graph at %q", shared.ErrValidation, curr.AssessmentID)
		}
		visited[curr.AssessmentID] = true

		pred, ok := byID[curr.PredecessorAssessmentID]
		if !ok {
			return nil, fmt.Errorf("%w: predecessor %q not found for member %q", shared.ErrNotFound, curr.PredecessorAssessmentID, curr.AssessmentID)
		}
		ancestors = append(ancestors, pred)
		curr = pred
	}

	return ancestors, nil
}

// DeriveDescendants returns all descendant members reachable from assessmentID.
// Results are deterministically sorted by RetestNumber ASC, AssessmentID ASC.
func DeriveDescendants(members []Member, assessmentID shared.ID) ([]Member, error) {
	childrenMap := make(map[shared.ID][]Member)
	byID := make(map[shared.ID]Member, len(members))

	for _, m := range members {
		byID[m.AssessmentID] = m
		if !m.PredecessorAssessmentID.IsZero() {
			childrenMap[m.PredecessorAssessmentID] = append(childrenMap[m.PredecessorAssessmentID], m)
		}
	}

	if _, exists := byID[assessmentID]; !exists {
		return nil, fmt.Errorf("%w: member %q not found", shared.ErrNotFound, assessmentID)
	}

	var descendants []Member
	visited := make(map[shared.ID]bool)
	queue := []shared.ID{assessmentID}

	for len(queue) > 0 {
		currID := queue[0]
		queue = queue[1:]

		for _, child := range childrenMap[currID] {
			if visited[child.AssessmentID] {
				return nil, fmt.Errorf("%w: cycle detected in member graph at %q", shared.ErrValidation, child.AssessmentID)
			}
			visited[child.AssessmentID] = true
			descendants = append(descendants, child)
			queue = append(queue, child.AssessmentID)
		}
	}

	SortMembers(descendants)
	return descendants, nil
}

// IsAncestor reports whether ancestorID is in the direct ancestry chain of descendantID.
func IsAncestor(members []Member, ancestorID, descendantID shared.ID) (bool, error) {
	if ancestorID == descendantID {
		return false, nil
	}
	ancestors, err := DeriveAncestors(members, descendantID)
	if err != nil {
		return false, err
	}
	for _, a := range ancestors {
		if a.AssessmentID == ancestorID {
			return true, nil
		}
	}
	return false, nil
}

// SortMembers sorts a slice of Member structs deterministically: RetestNumber ASC, AssessmentID ASC.
func SortMembers(members []Member) {
	sort.Slice(members, func(i, j int) bool {
		if members[i].RetestNumber != members[j].RetestNumber {
			return members[i].RetestNumber < members[j].RetestNumber
		}
		return members[i].AssessmentID < members[j].AssessmentID
	})
}
