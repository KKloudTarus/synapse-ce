package assessmentcycle

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service coordinates domain rules, multi-repository atomicity, and audit logging for Assessment Cycles.
type Service struct {
	cycles      ports.AssessmentCycleRepository
	engagements ports.EngagementRepository
	assets      ports.BusinessAssetRepository
	projects    ports.ProjectRepository
	tx          ports.TenantTransactionRunner
	ids         ports.IDGenerator
	clock       ports.Clock
	audit       ports.AuditLogger
}

// NewService constructs a validated Assessment Cycle service.
func NewService(
	cycles ports.AssessmentCycleRepository,
	engagements ports.EngagementRepository,
	assets ports.BusinessAssetRepository,
	projects ports.ProjectRepository,
	tx ports.TenantTransactionRunner,
	ids ports.IDGenerator,
	clock ports.Clock,
	audit ports.AuditLogger,
) (*Service, error) {
	if cycles == nil {
		return nil, fmt.Errorf("%w: assessment cycle repository is required", shared.ErrValidation)
	}
	if engagements == nil {
		return nil, fmt.Errorf("%w: engagement repository is required", shared.ErrValidation)
	}
	if tx == nil {
		return nil, fmt.Errorf("%w: tenant transaction runner is required", shared.ErrValidation)
	}
	if ids == nil {
		return nil, fmt.Errorf("%w: id generator is required", shared.ErrValidation)
	}
	if clock == nil {
		return nil, fmt.Errorf("%w: clock is required", shared.ErrValidation)
	}

	return &Service{
		cycles:      cycles,
		engagements: engagements,
		assets:      assets,
		projects:    projects,
		tx:          tx,
		ids:         ids,
		clock:       clock,
		audit:       audit,
	}, nil
}

type CreateInitialCycleInput struct {
	TenantID         shared.ID
	Name             string
	BoundaryKind     assessmentcycle.BoundaryKind
	BusinessAssetID  shared.ID
	ProjectID        shared.ID
	RootAssessmentID shared.ID
	Actor            string
}

// CreateInitialCycle atomically creates an AssessmentCycle and its root initial Member.
func (s *Service) CreateInitialCycle(ctx context.Context, in CreateInitialCycleInput) (*assessmentcycle.AssessmentCycle, *assessmentcycle.Member, error) {
	tenantID := shared.TenantOrDefault(in.TenantID)
	if tenantID.IsZero() || in.RootAssessmentID.IsZero() {
		return nil, nil, fmt.Errorf("%w: tenant id and root assessment id are required", shared.ErrValidation)
	}

	if err := assessmentcycle.ValidateBoundaryEnforcement(in.BoundaryKind, in.BusinessAssetID, in.ProjectID); err != nil {
		return nil, nil, err
	}

	var createdCycle *assessmentcycle.AssessmentCycle
	var createdRoot *assessmentcycle.Member

	err := s.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		// 1. Validate BusinessAsset if boundary is asset or asset_project
		if in.BoundaryKind == assessmentcycle.BoundaryAsset || in.BoundaryKind == assessmentcycle.BoundaryAssetProject {
			if s.assets != nil {
				assetObj, err := s.assets.GetBusinessAssetByID(txCtx, tenantID, in.BusinessAssetID)
				if err != nil {
					return fmt.Errorf("%w: business asset %q validation failed: %v", shared.ErrValidation, in.BusinessAssetID, err)
				}
				if !assetObj.AcceptsAssignments() {
					return fmt.Errorf("%w: business asset %q does not accept assignments (retired)", shared.ErrValidation, in.BusinessAssetID)
				}
			}
		}

		// 2. Validate Asset-Project link if boundary is asset_project
		if in.BoundaryKind == assessmentcycle.BoundaryAssetProject && s.assets != nil {
			projects, err := s.assets.ListBusinessAssetProjects(txCtx, tenantID, in.BusinessAssetID)
			if err != nil {
				return fmt.Errorf("%w: list business asset projects: %v", shared.ErrValidation, err)
			}
			foundLink := false
			for _, p := range projects {
				if p.ComponentID == in.ProjectID {
					foundLink = true
					break
				}
			}
			if !foundLink {
				return fmt.Errorf("%w: project %q is not associated with business asset %q", shared.ErrValidation, in.ProjectID, in.BusinessAssetID)
			}
		}

		// 3. Validate Project if boundary is project
		if in.BoundaryKind == assessmentcycle.BoundaryProject && s.projects != nil {
			if _, err := s.projects.GetByID(txCtx, tenantID, in.ProjectID); err != nil {
				return fmt.Errorf("%w: project %q validation failed: %v", shared.ErrValidation, in.ProjectID, err)
			}
		}

		// 4. Validate Root Assessment
		eng, err := s.engagements.GetByID(txCtx, in.RootAssessmentID)
		if err != nil {
			return fmt.Errorf("%w: load root assessment %q: %v", shared.ErrNotFound, in.RootAssessmentID, err)
		}
		if eng.TenantID != tenantID {
			return fmt.Errorf("%w: root assessment %q does not belong to tenant %q", shared.ErrNotFound, in.RootAssessmentID, tenantID)
		}

		// Rule #10: Hidden Project analysis-context Engagements cannot become Cycle members
		if !eng.ProjectID.IsZero() {
			return assessmentcycle.ErrHiddenProjectContext
		}

		// Verify boundary matching against assessment
		switch in.BoundaryKind {
		case assessmentcycle.BoundaryStandalone:
			if !eng.BusinessAssetID.IsZero() {
				return fmt.Errorf("%w: standalone cycle requires assessment with no business asset, but found %q", shared.ErrValidation, eng.BusinessAssetID)
			}
		case assessmentcycle.BoundaryAsset, assessmentcycle.BoundaryAssetProject:
			if eng.BusinessAssetID != in.BusinessAssetID {
				return fmt.Errorf("%w: assessment business asset %q does not match cycle business asset %q", shared.ErrValidation, eng.BusinessAssetID, in.BusinessAssetID)
			}
		}

		// 5. Ensure root assessment does not already belong to any cycle
		existingCycle, err := s.cycles.GetCycleByAssessment(txCtx, tenantID, in.RootAssessmentID)
		if err == nil && existingCycle != nil {
			return assessmentcycle.ErrAssessmentAlreadyInCycle
		}
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return err
		}

		// 6. Build domain objects
		now := s.clock.Now().UTC()
		cycleID := s.ids.NewID()

		cycle, err := assessmentcycle.NewAssessmentCycle(
			cycleID, tenantID, in.Name, in.BoundaryKind,
			in.BusinessAssetID, in.ProjectID, in.RootAssessmentID,
			in.Actor, now,
		)
		if err != nil {
			return err
		}

		rootMember, err := assessmentcycle.NewInitialMember(tenantID, cycleID, in.RootAssessmentID, in.Actor, now)
		if err != nil {
			return err
		}

		// 7. Persist Cycle + Root Member atomically
		if err := s.cycles.CreateCycle(txCtx, cycle); err != nil {
			return err
		}
		if err := s.cycles.CreateMember(txCtx, rootMember); err != nil {
			return err
		}

		// 8. Audit event
		if s.audit != nil {
			if err := s.audit.Record(txCtx, ports.AuditEntry{
				Actor:  in.Actor,
				Action: "assessment_cycle.created",
				Target: cycleID.String(),
				Metadata: map[string]string{
					"tenant_id":          tenantID.String(),
					"boundary_kind":      string(in.BoundaryKind),
					"root_assessment_id": in.RootAssessmentID.String(),
				},
				At: now,
			}); err != nil {
				// The audit append runs inside a savepoint on this transaction, so a failure leaves the transaction usable and rolling the whole unit back is a choice rather than a necessity. It is the right choice: a committed state change with no attributable record is what the append-only chain exists to prevent.
				return fmt.Errorf("record audit entry: %w", err)
			}
		}

		createdCycle = cycle
		createdRoot = rootMember
		return nil
	})

	return createdCycle, createdRoot, err
}

type CreateRetestInput struct {
	TenantID                shared.ID
	CycleID                 shared.ID
	PredecessorAssessmentID shared.ID
	NewAssessmentID         shared.ID
	ExpectedCycleVersion    int64
	Actor                   string
}

// CreateRetest atomically adds a new re-test member to an open AssessmentCycle and updates the cycle sequence.
func (s *Service) CreateRetest(ctx context.Context, in CreateRetestInput) (*assessmentcycle.Member, error) {
	tenantID := shared.TenantOrDefault(in.TenantID)
	if tenantID.IsZero() || in.CycleID.IsZero() || in.PredecessorAssessmentID.IsZero() || in.NewAssessmentID.IsZero() {
		return nil, fmt.Errorf("%w: tenant, cycle, predecessor, and new assessment ids are required", shared.ErrValidation)
	}

	var createdMember *assessmentcycle.Member

	err := s.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		// 1. Lock cycle row for update
		cycle, err := s.cycles.LockCycleForUpdate(txCtx, tenantID, in.CycleID)
		if err != nil {
			return err
		}
		if cycle.Status != assessmentcycle.StatusOpen {
			return fmt.Errorf("%w: cannot add retest to non-open cycle (status: %s)", shared.ErrValidation, cycle.Status)
		}

		// 2. Validate predecessor member
		predMember, err := s.cycles.GetMember(txCtx, tenantID, in.CycleID, in.PredecessorAssessmentID)
		if err != nil {
			return fmt.Errorf("%w: predecessor %q not found in cycle: %v", shared.ErrNotFound, in.PredecessorAssessmentID, err)
		}
		if predMember.IsArchived() {
			return fmt.Errorf("%w: predecessor %q is archived", shared.ErrValidation, in.PredecessorAssessmentID)
		}

		// 3. Validate new assessment
		eng, err := s.engagements.GetByID(txCtx, in.NewAssessmentID)
		if err != nil {
			return fmt.Errorf("%w: load new assessment %q: %v", shared.ErrNotFound, in.NewAssessmentID, err)
		}
		if eng.TenantID != tenantID {
			return fmt.Errorf("%w: new assessment %q does not belong to tenant %q", shared.ErrNotFound, in.NewAssessmentID, tenantID)
		}

		// Rule #10: Hidden Project analysis-context Engagements cannot become Cycle members
		if !eng.ProjectID.IsZero() {
			return assessmentcycle.ErrHiddenProjectContext
		}

		// Boundary check
		switch cycle.BoundaryKind {
		case assessmentcycle.BoundaryStandalone:
			if !eng.BusinessAssetID.IsZero() {
				return fmt.Errorf("%w: standalone cycle requires assessment with no business asset", shared.ErrValidation)
			}
		case assessmentcycle.BoundaryAsset, assessmentcycle.BoundaryAssetProject:
			if eng.BusinessAssetID != cycle.BusinessAssetID {
				return fmt.Errorf("%w: assessment business asset %q does not match cycle business asset %q", shared.ErrValidation, eng.BusinessAssetID, cycle.BusinessAssetID)
			}
		}

		// Ensure new assessment does not already belong to any cycle
		existingCycle, err := s.cycles.GetCycleByAssessment(txCtx, tenantID, in.NewAssessmentID)
		if err == nil && existingCycle != nil {
			return assessmentcycle.ErrAssessmentAlreadyInCycle
		}
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return err
		}

		// 4. Domain mutation on cycle
		now := s.clock.Now().UTC()
		expectedVer := in.ExpectedCycleVersion
		if expectedVer == 0 {
			expectedVer = cycle.Version
		}

		retestNumber, err := cycle.AdvanceRetest(in.NewAssessmentID, in.PredecessorAssessmentID, expectedVer, in.Actor, now)
		if err != nil {
			return err
		}

		// 5. Build member
		retestMember, err := assessmentcycle.NewRetestMember(
			tenantID, in.CycleID, in.NewAssessmentID, in.PredecessorAssessmentID,
			retestNumber, in.Actor, now,
		)
		if err != nil {
			return err
		}

		// 6. Persist changes
		if err := s.cycles.UpdateCycleCAS(txCtx, cycle, expectedVer); err != nil {
			return err
		}
		if err := s.cycles.CreateMember(txCtx, retestMember); err != nil {
			return err
		}

		// 7. Audit event
		if s.audit != nil {
			if err := s.audit.Record(txCtx, ports.AuditEntry{
				Actor:  in.Actor,
				Action: "assessment_cycle.retest_created",
				Target: in.CycleID.String(),
				Metadata: map[string]string{
					"tenant_id":        tenantID.String(),
					"assessment_id":    in.NewAssessmentID.String(),
					"predecessor_id":   in.PredecessorAssessmentID.String(),
					"retest_number":    fmt.Sprintf("%d", retestNumber),
					"selected_head_id": cycle.SelectedHeadAssessmentID.String(),
				},
				At: now,
			}); err != nil {
				// The audit append runs inside a savepoint on this transaction, so a failure leaves the transaction usable and rolling the whole unit back is a choice rather than a necessity. It is the right choice: a committed state change with no attributable record is what the append-only chain exists to prevent.
				return fmt.Errorf("record audit entry: %w", err)
			}
		}

		createdMember = retestMember
		return nil
	})

	return createdMember, err
}

type ReparentInput struct {
	TenantID                   shared.ID
	CycleID                    shared.ID
	AssessmentID               shared.ID
	NewPredecessorAssessmentID shared.ID
	ExpectedMemberVersion      int64
	ExpectedCycleVersion       int64
	Actor                      string
}

// ReparentWithinCycle atomically changes a re-test member's predecessor within the same cycle.
func (s *Service) ReparentWithinCycle(ctx context.Context, in ReparentInput) error {
	tenantID := shared.TenantOrDefault(in.TenantID)
	if tenantID.IsZero() || in.CycleID.IsZero() || in.AssessmentID.IsZero() || in.NewPredecessorAssessmentID.IsZero() {
		return fmt.Errorf("%w: tenant, cycle, assessment, and new predecessor ids are required", shared.ErrValidation)
	}

	return s.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		// 1. Lock cycle
		cycle, err := s.cycles.LockCycleForUpdate(txCtx, tenantID, in.CycleID)
		if err != nil {
			return err
		}
		if cycle.Status != assessmentcycle.StatusOpen {
			return fmt.Errorf("%w: cannot reparent in non-open cycle (status: %s)", shared.ErrValidation, cycle.Status)
		}

		// 2. Load target member
		targetMember, err := s.cycles.GetMember(txCtx, tenantID, in.CycleID, in.AssessmentID)
		if err != nil {
			return err
		}
		if targetMember.IsRoot() {
			return fmt.Errorf("%w: root member cannot be reparented", shared.ErrValidation)
		}
		if targetMember.IsArchived() {
			return fmt.Errorf("%w: cannot reparent archived member", shared.ErrValidation)
		}

		// 3. Load all members to validate graph acyclicity
		members, err := s.cycles.ListMembers(txCtx, tenantID, in.CycleID)
		if err != nil {
			return err
		}

		// 4. Validate new predecessor
		predMember, err := s.cycles.GetMember(txCtx, tenantID, in.CycleID, in.NewPredecessorAssessmentID)
		if err != nil {
			return fmt.Errorf("%w: new predecessor %q not found in cycle: %v", shared.ErrNotFound, in.NewPredecessorAssessmentID, err)
		}
		if predMember.IsArchived() {
			return fmt.Errorf("%w: cannot reparent to archived predecessor", shared.ErrValidation)
		}

		// Check if new predecessor is currently a descendant of targetMember
		isDescendant, err := assessmentcycle.IsAncestor(members, in.AssessmentID, in.NewPredecessorAssessmentID)
		if err != nil {
			return err
		}
		if isDescendant {
			return fmt.Errorf("%w: cannot reparent to a descendant (cycle detected)", shared.ErrValidation)
		}

		// 5. Mutate member
		memberExpectedVer := in.ExpectedMemberVersion
		if memberExpectedVer == 0 {
			memberExpectedVer = targetMember.RelationshipVersion
		}
		if err := targetMember.Reparent(in.NewPredecessorAssessmentID, memberExpectedVer); err != nil {
			return err
		}

		// 6. Mutate cycle version
		now := s.clock.Now().UTC()
		cycleExpectedVer := in.ExpectedCycleVersion
		if cycleExpectedVer == 0 {
			cycleExpectedVer = cycle.Version
		}
		cycle.Version++
		cycle.UpdatedAt = now
		cycle.UpdatedBy = strings.TrimSpace(in.Actor)

		// 7. Persist CAS
		if err := s.cycles.UpdateMemberCAS(txCtx, targetMember, memberExpectedVer); err != nil {
			return err
		}
		if err := s.cycles.UpdateCycleCAS(txCtx, cycle, cycleExpectedVer); err != nil {
			return err
		}

		// 8. Audit event
		if s.audit != nil {
			if err := s.audit.Record(txCtx, ports.AuditEntry{
				Actor:  in.Actor,
				Action: "assessment_cycle.reparented",
				Target: in.CycleID.String(),
				Metadata: map[string]string{
					"tenant_id":          tenantID.String(),
					"assessment_id":      in.AssessmentID.String(),
					"new_predecessor_id": in.NewPredecessorAssessmentID.String(),
				},
				At: now,
			}); err != nil {
				// The audit append runs inside a savepoint on this transaction, so a failure leaves the transaction usable and rolling the whole unit back is a choice rather than a necessity. It is the right choice: a committed state change with no attributable record is what the append-only chain exists to prevent.
				return fmt.Errorf("record audit entry: %w", err)
			}
		}

		return nil
	})
}

type SelectHeadInput struct {
	TenantID             shared.ID
	CycleID              shared.ID
	TargetAssessmentID   shared.ID
	ExpectedCycleVersion int64
	Actor                string
}

// SelectHead explicitly changes the selected head of an open AssessmentCycle to an active branch head.
func (s *Service) SelectHead(ctx context.Context, in SelectHeadInput) error {
	tenantID := shared.TenantOrDefault(in.TenantID)
	if tenantID.IsZero() || in.CycleID.IsZero() || in.TargetAssessmentID.IsZero() {
		return fmt.Errorf("%w: tenant, cycle, and target assessment ids are required", shared.ErrValidation)
	}

	return s.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		cycle, err := s.cycles.LockCycleForUpdate(txCtx, tenantID, in.CycleID)
		if err != nil {
			return err
		}
		if cycle.Status != assessmentcycle.StatusOpen {
			return fmt.Errorf("%w: cannot select head on non-open cycle (status: %s)", shared.ErrValidation, cycle.Status)
		}

		members, err := s.cycles.ListMembers(txCtx, tenantID, in.CycleID)
		if err != nil {
			return err
		}

		branchHeads := assessmentcycle.DeriveBranchHeads(members)
		isBranchHead := false
		for _, h := range branchHeads {
			if h.AssessmentID == in.TargetAssessmentID {
				isBranchHead = true
				break
			}
		}
		if !isBranchHead {
			return assessmentcycle.ErrInvalidBranchHead
		}

		now := s.clock.Now().UTC()
		expectedVer := in.ExpectedCycleVersion
		if expectedVer == 0 {
			expectedVer = cycle.Version
		}

		if err := cycle.SelectHead(in.TargetAssessmentID, expectedVer, in.Actor, now); err != nil {
			return err
		}

		if err := s.cycles.UpdateCycleCAS(txCtx, cycle, expectedVer); err != nil {
			return err
		}

		if s.audit != nil {
			if err := s.audit.Record(txCtx, ports.AuditEntry{
				Actor:  in.Actor,
				Action: "assessment_cycle.head_selected",
				Target: in.CycleID.String(),
				Metadata: map[string]string{
					"tenant_id":        tenantID.String(),
					"selected_head_id": in.TargetAssessmentID.String(),
				},
				At: now,
			}); err != nil {
				// The audit append runs inside a savepoint on this transaction, so a failure leaves the transaction usable and rolling the whole unit back is a choice rather than a necessity. It is the right choice: a committed state change with no attributable record is what the append-only chain exists to prevent.
				return fmt.Errorf("record audit entry: %w", err)
			}
		}

		return nil
	})
}

type ArchiveMemberInput struct {
	TenantID              shared.ID
	CycleID               shared.ID
	AssessmentID          shared.ID
	ExpectedMemberVersion int64
	ExpectedCycleVersion  int64
	Actor                 string
}

// ArchiveMember soft-deletes a non-root, non-selected-head member from an open AssessmentCycle.
func (s *Service) ArchiveMember(ctx context.Context, in ArchiveMemberInput) error {
	tenantID := shared.TenantOrDefault(in.TenantID)
	if tenantID.IsZero() || in.CycleID.IsZero() || in.AssessmentID.IsZero() {
		return fmt.Errorf("%w: tenant, cycle, and assessment ids are required", shared.ErrValidation)
	}

	return s.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		cycle, err := s.cycles.LockCycleForUpdate(txCtx, tenantID, in.CycleID)
		if err != nil {
			return err
		}
		if cycle.Status != assessmentcycle.StatusOpen {
			return fmt.Errorf("%w: cannot archive member in non-open cycle (status: %s)", shared.ErrValidation, cycle.Status)
		}

		if cycle.SelectedHeadAssessmentID == in.AssessmentID {
			return assessmentcycle.ErrCannotArchiveSelectedHead
		}

		member, err := s.cycles.GetMember(txCtx, tenantID, in.CycleID, in.AssessmentID)
		if err != nil {
			return err
		}
		if member.IsRoot() {
			return assessmentcycle.ErrCannotArchiveRoot
		}

		now := s.clock.Now().UTC()
		memberExpectedVer := in.ExpectedMemberVersion
		if memberExpectedVer == 0 {
			memberExpectedVer = member.RelationshipVersion
		}

		if err := member.Archive(memberExpectedVer, now); err != nil {
			return err
		}

		cycleExpectedVer := in.ExpectedCycleVersion
		if cycleExpectedVer == 0 {
			cycleExpectedVer = cycle.Version
		}
		cycle.Version++
		cycle.UpdatedAt = now
		cycle.UpdatedBy = strings.TrimSpace(in.Actor)

		if err := s.cycles.UpdateMemberCAS(txCtx, member, memberExpectedVer); err != nil {
			return err
		}
		if err := s.cycles.UpdateCycleCAS(txCtx, cycle, cycleExpectedVer); err != nil {
			return err
		}

		if s.audit != nil {
			if err := s.audit.Record(txCtx, ports.AuditEntry{
				Actor:  in.Actor,
				Action: "assessment_cycle.member_archived",
				Target: in.CycleID.String(),
				Metadata: map[string]string{
					"tenant_id":     tenantID.String(),
					"assessment_id": in.AssessmentID.String(),
				},
				At: now,
			}); err != nil {
				// The audit append runs inside a savepoint on this transaction, so a failure leaves the transaction usable and rolling the whole unit back is a choice rather than a necessity. It is the right choice: a committed state change with no attributable record is what the append-only chain exists to prevent.
				return fmt.Errorf("record audit entry: %w", err)
			}
		}

		return nil
	})
}

type ReopenCycleInput struct {
	TenantID             shared.ID
	CycleID              shared.ID
	ExpectedCycleVersion int64
	Actor                string
}

// ReopenCycle transitions a completed AssessmentCycle back to open.
func (s *Service) ReopenCycle(ctx context.Context, in ReopenCycleInput) error {
	tenantID := shared.TenantOrDefault(in.TenantID)
	if tenantID.IsZero() || in.CycleID.IsZero() {
		return fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}

	return s.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		cycle, err := s.cycles.LockCycleForUpdate(txCtx, tenantID, in.CycleID)
		if err != nil {
			return err
		}

		now := s.clock.Now().UTC()
		expectedVer := in.ExpectedCycleVersion
		if expectedVer == 0 {
			expectedVer = cycle.Version
		}

		if err := cycle.Transition(assessmentcycle.StatusOpen, expectedVer, in.Actor, now); err != nil {
			return err
		}

		if err := s.cycles.UpdateCycleCAS(txCtx, cycle, expectedVer); err != nil {
			return err
		}

		if s.audit != nil {
			if err := s.audit.Record(txCtx, ports.AuditEntry{
				Actor:  in.Actor,
				Action: "assessment_cycle.reopened",
				Target: in.CycleID.String(),
				Metadata: map[string]string{
					"tenant_id": tenantID.String(),
				},
				At: now,
			}); err != nil {
				// The audit append runs inside a savepoint on this transaction, so a failure leaves the transaction usable and rolling the whole unit back is a choice rather than a necessity. It is the right choice: a committed state change with no attributable record is what the append-only chain exists to prevent.
				return fmt.Errorf("record audit entry: %w", err)
			}
		}

		return nil
	})
}

type ArchiveCycleInput struct {
	TenantID             shared.ID
	CycleID              shared.ID
	ExpectedCycleVersion int64
	Actor                string
}

// ArchiveCycle transitions an open or completed AssessmentCycle to archived.
func (s *Service) ArchiveCycle(ctx context.Context, in ArchiveCycleInput) error {
	tenantID := shared.TenantOrDefault(in.TenantID)
	if tenantID.IsZero() || in.CycleID.IsZero() {
		return fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}

	return s.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		cycle, err := s.cycles.LockCycleForUpdate(txCtx, tenantID, in.CycleID)
		if err != nil {
			return err
		}

		now := s.clock.Now().UTC()
		expectedVer := in.ExpectedCycleVersion
		if expectedVer == 0 {
			expectedVer = cycle.Version
		}

		if err := cycle.Transition(assessmentcycle.StatusArchived, expectedVer, in.Actor, now); err != nil {
			return err
		}

		if err := s.cycles.UpdateCycleCAS(txCtx, cycle, expectedVer); err != nil {
			return err
		}

		if s.audit != nil {
			if err := s.audit.Record(txCtx, ports.AuditEntry{
				Actor:  in.Actor,
				Action: "assessment_cycle.archived",
				Target: in.CycleID.String(),
				Metadata: map[string]string{
					"tenant_id": tenantID.String(),
				},
				At: now,
			}); err != nil {
				// The audit append runs inside a savepoint on this transaction, so a failure leaves the transaction usable and rolling the whole unit back is a choice rather than a necessity. It is the right choice: a committed state change with no attributable record is what the append-only chain exists to prevent.
				return fmt.Errorf("record audit entry: %w", err)
			}
		}

		return nil
	})
}

// GetCycle retrieves an AssessmentCycle by ID.
func (s *Service) GetCycle(ctx context.Context, tenantID, cycleID shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	return s.cycles.GetCycle(ctx, tenantID, cycleID)
}

// GetCycleByAssessment retrieves an AssessmentCycle by one of its Assessment IDs.
func (s *Service) GetCycleByAssessment(ctx context.Context, tenantID, assessmentID shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	return s.cycles.GetCycleByAssessment(ctx, tenantID, assessmentID)
}

// ListMembers retrieves all members of a cycle, deterministically sorted.
func (s *Service) ListMembers(ctx context.Context, tenantID, cycleID shared.ID) ([]assessmentcycle.Member, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	return s.cycles.ListMembers(ctx, tenantID, cycleID)
}

// ListBranchHeads returns all active branch heads of a cycle.
func (s *Service) ListBranchHeads(ctx context.Context, tenantID, cycleID shared.ID) ([]assessmentcycle.Member, error) {
	members, err := s.ListMembers(ctx, tenantID, cycleID)
	if err != nil {
		return nil, err
	}
	return assessmentcycle.DeriveBranchHeads(members), nil
}

// ListAncestors returns the ancestor lineage of an assessment within a cycle.
func (s *Service) ListAncestors(ctx context.Context, tenantID, cycleID, assessmentID shared.ID) ([]assessmentcycle.Member, error) {
	members, err := s.ListMembers(ctx, tenantID, cycleID)
	if err != nil {
		return nil, err
	}
	return assessmentcycle.DeriveAncestors(members, assessmentID)
}

// ListDescendants returns all descendant re-tests spawned from an assessment within a cycle.
func (s *Service) ListDescendants(ctx context.Context, tenantID, cycleID, assessmentID shared.ID) ([]assessmentcycle.Member, error) {
	members, err := s.ListMembers(ctx, tenantID, cycleID)
	if err != nil {
		return nil, err
	}
	return assessmentcycle.DeriveDescendants(members, assessmentID)
}

// IsAncestor reports whether ancestorID is in the direct ancestry chain of descendantID.
func (s *Service) IsAncestor(ctx context.Context, tenantID, cycleID, ancestorID, descendantID shared.ID) (bool, error) {
	members, err := s.ListMembers(ctx, tenantID, cycleID)
	if err != nil {
		return false, err
	}
	return assessmentcycle.IsAncestor(members, ancestorID, descendantID)
}
