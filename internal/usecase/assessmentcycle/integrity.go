package assessmentcycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	DefaultAssessmentCycleIntegrityBatch = 500
	MaxAssessmentCycleIntegrityBatch     = 2000
	defaultAssessmentCycleIntegrityLease = 10 * time.Minute
	assessmentCycleIntegrityRetries      = 3
)

const (
	IntegrityCoverageMissing        = "coverage_missing"
	IntegrityCoverageMultiple       = "coverage_multiple"
	IntegrityCycleMissing           = "cycle_missing"
	IntegrityMemberSourceMissing    = "member_source_missing"
	IntegrityRootCardinality        = "root_cardinality"
	IntegrityRootMismatch           = "root_mismatch"
	IntegrityMemberTenantMismatch   = "member_tenant_mismatch"
	IntegrityMemberCycleMismatch    = "member_cycle_mismatch"
	IntegrityBoundaryMismatch       = "frozen_boundary_mismatch"
	IntegrityHiddenContextMember    = "hidden_project_context_member"
	IntegritySelectedHeadMissing    = "selected_head_missing"
	IntegritySelectedHeadArchived   = "selected_head_archived"
	IntegritySelectedHeadNotLeaf    = "selected_head_not_leaf"
	IntegritySelectedHeadIneligible = "selected_head_ineligible"
	IntegrityRetestNumberDuplicate  = "retest_number_duplicate"
	IntegrityRetestNumberGap        = "retest_number_gap"
	IntegrityNextRetestNotMonotonic = "next_retest_not_monotonic"
	IntegrityPredecessorMissing     = "predecessor_missing"
	IntegrityGraphCycle             = "graph_cycle"
	IntegritySourceTargetCountDrift = "source_target_count_mismatch"
)

type AssessmentCycleIntegrityObserver interface {
	ObserveAssessmentCycleIntegritySubject(outcome string)
	ObserveAssessmentCycleIntegrityRun(state string)
}

type IntegrityVerifier struct {
	source   ports.AssessmentCycleIntegritySource
	store    ports.AssessmentCycleIntegrityStore
	ids      ports.IDGenerator
	clock    ports.Clock
	audit    ports.AuditLogger
	observer AssessmentCycleIntegrityObserver
}

func NewIntegrityVerifier(source ports.AssessmentCycleIntegritySource, store ports.AssessmentCycleIntegrityStore, ids ports.IDGenerator, clock ports.Clock, audit ports.AuditLogger, observer AssessmentCycleIntegrityObserver) (*IntegrityVerifier, error) {
	if source == nil || store == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: assessment cycle integrity dependencies are required", shared.ErrValidation)
	}
	return &IntegrityVerifier{source: source, store: store, ids: ids, clock: clock, audit: audit, observer: observer}, nil
}

type IntegrityRequest struct {
	TenantID      shared.ID
	Actor         string
	LeaseOwner    string
	BatchSize     int
	LeaseDuration time.Duration
}

func (verifier *IntegrityVerifier) Run(ctx context.Context, request IntegrityRequest) (ports.AssessmentCycleIntegrityRun, error) {
	tenantID := shared.TenantOrDefault(request.TenantID)
	actor, leaseOwner := strings.TrimSpace(request.Actor), strings.TrimSpace(request.LeaseOwner)
	if tenantID.IsZero() || actor == "" || len(actor) > 256 || leaseOwner == "" || len(leaseOwner) > 256 {
		return ports.AssessmentCycleIntegrityRun{}, fmt.Errorf("%w: tenant, actor, and lease owner are required", shared.ErrValidation)
	}
	batchSize := request.BatchSize
	if batchSize == 0 {
		batchSize = DefaultAssessmentCycleIntegrityBatch
	}
	if batchSize < 1 || batchSize > MaxAssessmentCycleIntegrityBatch {
		return ports.AssessmentCycleIntegrityRun{}, fmt.Errorf("%w: batch size must be between 1 and %d", shared.ErrValidation, MaxAssessmentCycleIntegrityBatch)
	}
	leaseDuration := request.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultAssessmentCycleIntegrityLease
	}
	now := verifier.clock.Now().UTC()
	acquisitionID := verifier.ids.NewID()
	run, resumed, err := verifier.store.AcquireAssessmentCycleIntegrityRun(ctx, ports.AssessmentCycleIntegrityAcquireRequest{Run: ports.AssessmentCycleIntegrityRun{
		TenantID: tenantID, ID: acquisitionID, BatchSize: batchSize, SnapshotAt: now, State: ports.AssessmentCycleIntegrityRunning,
		LeaseOwner: leaseOwner, LeaseToken: acquisitionID, LeaseExpiresAt: now.Add(leaseDuration), CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
	}, LeaseDuration: leaseDuration})
	if err != nil {
		return ports.AssessmentCycleIntegrityRun{}, err
	}
	verifier.record(ctx, actor, "assessment_cycle.integrity_started", run.ID, map[string]string{
		"tenant_id": tenantID.String(), "resumed": strconv.FormatBool(resumed), "batch_size": strconv.Itoa(run.BatchSize),
	})
	for {
		if err := ctx.Err(); err != nil {
			return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityCancelled, actor, err)
		}
		subjects, err := retryIntegrity(ctx, func() ([]ports.AssessmentCycleIntegritySubject, error) {
			return verifier.source.ListAssessmentCycleIntegritySubjects(ctx, tenantID, run.CheckpointAssessment, run.SnapshotAt, run.BatchSize)
		})
		if err != nil {
			return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityFailed, actor, err)
		}
		if len(subjects) == 0 {
			counts, err := retryIntegrity(ctx, func() ([2]int, error) {
				eligible, memberships, err := verifier.source.CountAssessmentCycleIntegritySubjects(ctx, tenantID, run.SnapshotAt)
				return [2]int{eligible, memberships}, err
			})
			if err != nil {
				return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityFailed, actor, err)
			}
			eligible, memberships := counts[0], counts[1]
			if run.ScannedCount != eligible || (memberships != eligible && run.FindingCount == 0) {
				return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityFailed, actor, fmt.Errorf("%s: scanned=%d eligible=%d memberships=%d", IntegritySourceTargetCountDrift, run.ScannedCount, eligible, memberships))
			}
			return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityCompleted, actor, nil)
		}
		if len(subjects) > run.BatchSize {
			return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityFailed, actor, fmt.Errorf("integrity source returned %d rows for limit %d", len(subjects), run.BatchSize))
		}
		for _, subject := range subjects {
			if err := ctx.Err(); err != nil {
				return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityCancelled, actor, err)
			}
			if _, err := verifier.store.GetAssessmentCycleIntegritySubject(ctx, tenantID, run.ID, subject.AssessmentID); err == nil {
				continue
			} else if !errors.Is(err, shared.ErrNotFound) {
				return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityFailed, actor, err)
			}
			findings := verifyIntegritySubject(run.ID, subject, verifier.clock.Now().UTC())
			result := ports.AssessmentCycleIntegritySubjectResult{TenantID: tenantID, RunID: run.ID, AssessmentID: subject.AssessmentID, Clean: len(findings) == 0, FindingCount: len(findings), ProcessedAt: verifier.clock.Now().UTC()}
			created, err := retryIntegrity(ctx, func() (bool, error) {
				return verifier.store.SaveAssessmentCycleIntegritySubject(ctx, run.LeaseToken, verifier.clock.Now().UTC(), result, findings)
			})
			if err != nil {
				return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityFailed, actor, err)
			}
			if created && verifier.observer != nil {
				outcome := "clean"
				if len(findings) > 0 {
					outcome = "finding"
				}
				verifier.observer.ObserveAssessmentCycleIntegritySubject(outcome)
			}
		}
		checkpoint := subjects[len(subjects)-1].AssessmentID
		run, err = retryIntegrity(ctx, func() (ports.AssessmentCycleIntegrityRun, error) {
			return verifier.store.AdvanceAssessmentCycleIntegrityRun(ctx, tenantID, run.ID, leaseOwner, run.LeaseToken, checkpoint, verifier.clock.Now().UTC(), leaseDuration)
		})
		if err != nil {
			return verifier.finish(ctx, run, leaseOwner, ports.AssessmentCycleIntegrityFailed, actor, err)
		}
		verifier.record(ctx, actor, "assessment_cycle.integrity_batch_committed", run.ID, map[string]string{
			"tenant_id": tenantID.String(), "checkpoint_assessment_id": checkpoint.String(), "scanned_count": strconv.Itoa(run.ScannedCount), "finding_count": strconv.Itoa(run.FindingCount),
		})
	}
}

func verifyIntegritySubject(runID shared.ID, subject ports.AssessmentCycleIntegritySubject, detectedAt time.Time) []ports.AssessmentCycleIntegrityFinding {
	var findings []ports.AssessmentCycleIntegrityFinding
	add := func(reason, severity string, cycleID, memberID shared.ID) {
		findings = append(findings, newIntegrityFinding(runID, subject.TenantID, subject.AssessmentID, cycleID, memberID, reason, severity, detectedAt))
	}
	membershipCount := 0
	for _, cycle := range subject.Cycles {
		membershipCount += cycle.SubjectMembershipCount
	}
	if membershipCount == 0 {
		add(IntegrityCoverageMissing, "high", "", "")
		return findings
	}
	if membershipCount != 1 {
		add(IntegrityCoverageMultiple, "critical", "", "")
	}
	for _, record := range subject.Cycles {
		cycle := record.Cycle
		if !record.CycleExists {
			add(IntegrityCycleMissing, "critical", cycle.ID, "")
			continue
		}
		membersByID := make(map[shared.ID]ports.AssessmentCycleIntegrityMember, len(record.Members))
		activeChildren := map[shared.ID]bool{}
		rootCount, maxRetest := 0, 0
		retestNumbers := map[int]bool{}
		for _, wrapped := range record.Members {
			member := wrapped.Member
			membersByID[member.AssessmentID] = wrapped
			if !wrapped.AssessmentExists {
				add(IntegrityMemberSourceMissing, "critical", cycle.ID, member.AssessmentID)
			}
			if member.IsRoot() {
				rootCount++
			}
			if member.TenantID != subject.TenantID || member.TenantID != cycle.TenantID {
				add(IntegrityMemberTenantMismatch, "critical", cycle.ID, member.AssessmentID)
			}
			if member.CycleID != cycle.ID {
				add(IntegrityMemberCycleMismatch, "critical", cycle.ID, member.AssessmentID)
			}
			if !wrapped.ProjectID.IsZero() {
				add(IntegrityHiddenContextMember, "critical", cycle.ID, member.AssessmentID)
			}
			boundaryValid := (cycle.BoundaryKind == cycledom.BoundaryStandalone && wrapped.BusinessAssetID.IsZero()) ||
				(cycle.BoundaryKind == cycledom.BoundaryAsset && wrapped.BusinessAssetID == cycle.BusinessAssetID)
			if !boundaryValid {
				add(IntegrityBoundaryMismatch, "high", cycle.ID, member.AssessmentID)
			}
			if !member.PredecessorAssessmentID.IsZero() && !member.IsArchived() {
				activeChildren[member.PredecessorAssessmentID] = true
			}
			if member.RetestNumber > 0 {
				if retestNumbers[member.RetestNumber] {
					add(IntegrityRetestNumberDuplicate, "high", cycle.ID, member.AssessmentID)
				}
				retestNumbers[member.RetestNumber] = true
				if member.RetestNumber > maxRetest {
					maxRetest = member.RetestNumber
				}
			}
		}
		if rootCount != 1 {
			add(IntegrityRootCardinality, "critical", cycle.ID, "")
		}
		root, rootExists := membersByID[cycle.RootAssessmentID]
		if !rootExists || !root.Member.IsRoot() {
			add(IntegrityRootMismatch, "critical", cycle.ID, cycle.RootAssessmentID)
		}
		for number := 1; number <= maxRetest; number++ {
			if !retestNumbers[number] {
				add(IntegrityRetestNumberGap, "medium", cycle.ID, "")
				break
			}
		}
		if cycle.NextRetestNumber <= maxRetest {
			add(IntegrityNextRetestNotMonotonic, "high", cycle.ID, "")
		}
		for _, wrapped := range record.Members {
			member := wrapped.Member
			if !member.PredecessorAssessmentID.IsZero() {
				if _, ok := membersByID[member.PredecessorAssessmentID]; !ok {
					add(IntegrityPredecessorMissing, "critical", cycle.ID, member.AssessmentID)
				}
			}
		}
		if hasIntegrityGraphCycle(record.Members) {
			add(IntegrityGraphCycle, "critical", cycle.ID, "")
		}
		head, headExists := membersByID[cycle.SelectedHeadAssessmentID]
		switch {
		case !headExists:
			add(IntegritySelectedHeadMissing, "critical", cycle.ID, cycle.SelectedHeadAssessmentID)
		case head.Member.IsArchived():
			add(IntegritySelectedHeadArchived, "high", cycle.ID, head.Member.AssessmentID)
		case activeChildren[head.Member.AssessmentID]:
			add(IntegritySelectedHeadNotLeaf, "high", cycle.ID, head.Member.AssessmentID)
		case cycle.Status != cycledom.StatusArchived && head.AssessmentStatus == engdom.StatusArchived:
			add(IntegritySelectedHeadIneligible, "high", cycle.ID, head.Member.AssessmentID)
		}
	}
	sort.Slice(findings, func(left, right int) bool { return findings[left].OccurrenceID < findings[right].OccurrenceID })
	return findings
}

func hasIntegrityGraphCycle(members []ports.AssessmentCycleIntegrityMember) bool {
	predecessors := make(map[shared.ID]shared.ID, len(members))
	for _, member := range members {
		predecessors[member.Member.AssessmentID] = member.Member.PredecessorAssessmentID
	}
	for start := range predecessors {
		seen := map[shared.ID]bool{}
		for current := start; !current.IsZero(); current = predecessors[current] {
			if seen[current] {
				return true
			}
			seen[current] = true
			if _, exists := predecessors[current]; !exists {
				break
			}
		}
	}
	return false
}

type integrityRepairPlan struct {
	Action        string   `json:"action"`
	TargetID      string   `json:"target_id"`
	Preconditions []string `json:"preconditions"`
}

func newIntegrityFinding(runID, tenantID, assessmentID, cycleID, memberID shared.ID, reason, severity string, detectedAt time.Time) ports.AssessmentCycleIntegrityFinding {
	targetID := assessmentID.String()
	if !cycleID.IsZero() {
		targetID = cycleID.String()
	}
	plan, _ := json.Marshal(integrityRepairPlan{Action: integrityRepairAction(reason), TargetID: targetID, Preconditions: []string{"dual_write_disabled_for_repair", "operator_review_required", "backup_verified"}})
	sum := sha256.Sum256([]byte(strings.Join([]string{tenantID.String(), assessmentID.String(), cycleID.String(), memberID.String(), reason}, "\x00")))
	return ports.AssessmentCycleIntegrityFinding{
		TenantID: tenantID, RunID: runID, OccurrenceID: hex.EncodeToString(sum[:16]), AssessmentID: assessmentID, CycleID: cycleID, MemberID: memberID,
		ReasonCode: reason, Severity: severity, RepairPlan: plan, DetectedAt: detectedAt.UTC(),
	}
}

func integrityRepairAction(reason string) string {
	switch reason {
	case IntegrityCoverageMissing:
		return "create_singleton_cycle"
	case IntegrityCoverageMultiple, IntegrityGraphCycle, IntegrityRootCardinality, IntegrityRootMismatch:
		return "manual_relationship_repair"
	case IntegritySelectedHeadMissing, IntegritySelectedHeadArchived, IntegritySelectedHeadNotLeaf, IntegritySelectedHeadIneligible:
		return "select_eligible_leaf"
	case IntegrityNextRetestNotMonotonic, IntegrityRetestNumberDuplicate, IntegrityRetestNumberGap:
		return "rebuild_retest_allocation"
	default:
		return "review_and_repair_cycle"
	}
}

func (verifier *IntegrityVerifier) finish(ctx context.Context, run ports.AssessmentCycleIntegrityRun, leaseOwner string, state ports.AssessmentCycleIntegrityState, actor string, cause error) (ports.AssessmentCycleIntegrityRun, error) {
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	finished, err := verifier.store.FinishAssessmentCycleIntegrityRun(finishCtx, run.TenantID, run.ID, leaseOwner, run.LeaseToken, state, verifier.clock.Now().UTC())
	if err != nil {
		if cause != nil {
			return run, errors.Join(cause, err)
		}
		return run, err
	}
	if verifier.observer != nil {
		verifier.observer.ObserveAssessmentCycleIntegrityRun(string(state))
	}
	verifier.record(finishCtx, actor, "assessment_cycle.integrity_"+string(state), run.ID, map[string]string{
		"tenant_id": run.TenantID.String(), "scanned_count": strconv.Itoa(finished.ScannedCount), "clean_count": strconv.Itoa(finished.CleanCount), "finding_count": strconv.Itoa(finished.FindingCount),
	})
	if cause != nil {
		return finished, cause
	}
	return finished, nil
}

func (verifier *IntegrityVerifier) record(ctx context.Context, actor, action string, target shared.ID, metadata map[string]string) {
	if verifier.audit != nil {
		_ = verifier.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target.String(), Metadata: metadata, At: verifier.clock.Now().UTC()})
	}
}

func retryIntegrity[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	var zero T
	for attempt := 0; attempt < assessmentCycleIntegrityRetries; attempt++ {
		value, err := operation()
		if err == nil {
			return value, nil
		}
		if ctx.Err() != nil || errors.Is(err, shared.ErrValidation) || errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrConflict) {
			return zero, err
		}
		if attempt == assessmentCycleIntegrityRetries-1 {
			return zero, err
		}
	}
	return zero, nil
}
