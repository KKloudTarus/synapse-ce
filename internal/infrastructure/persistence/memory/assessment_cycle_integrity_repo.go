package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentCycleIntegrityRepository struct {
	mu          sync.Mutex
	engagements *EngagementRepository
	cycles      *AssessmentCycleRepository
	runs        map[shared.ID]map[shared.ID]ports.AssessmentCycleIntegrityRun
	subjects    map[shared.ID]map[shared.ID]map[shared.ID]ports.AssessmentCycleIntegritySubjectResult
	findings    map[shared.ID]map[shared.ID]map[string]ports.AssessmentCycleIntegrityFinding
}

func NewAssessmentCycleIntegrityRepository(engagements *EngagementRepository, cycles *AssessmentCycleRepository) *AssessmentCycleIntegrityRepository {
	return &AssessmentCycleIntegrityRepository{
		engagements: engagements, cycles: cycles,
		runs:     map[shared.ID]map[shared.ID]ports.AssessmentCycleIntegrityRun{},
		subjects: map[shared.ID]map[shared.ID]map[shared.ID]ports.AssessmentCycleIntegritySubjectResult{},
		findings: map[shared.ID]map[shared.ID]map[string]ports.AssessmentCycleIntegrityFinding{},
	}
}

var _ ports.AssessmentCycleIntegritySource = (*AssessmentCycleIntegrityRepository)(nil)
var _ ports.AssessmentCycleIntegrityStore = (*AssessmentCycleIntegrityRepository)(nil)

func (repository *AssessmentCycleIntegrityRepository) ListAssessmentCycleIntegritySubjects(_ context.Context, tenantID, after shared.ID, snapshotAt time.Time, limit int) ([]ports.AssessmentCycleIntegritySubject, error) {
	if repository.engagements == nil || repository.cycles == nil || snapshotAt.IsZero() || limit < 1 || limit > 2000 {
		return nil, fmt.Errorf("%w: assessment cycle integrity source is invalid", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.engagements.mu.RLock()
	repository.cycles.mu.Lock()
	defer repository.engagements.mu.RUnlock()
	defer repository.cycles.mu.Unlock()
	ids := make([]shared.ID, 0, limit)
	for id, engagement := range repository.engagements.data {
		if engagement.TenantID == tenantID && engagement.ProjectID.IsZero() && id > after && !engagement.Audit.CreatedAt.After(snapshotAt) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	if len(ids) > limit {
		ids = ids[:limit]
	}
	subjects := make([]ports.AssessmentCycleIntegritySubject, 0, len(ids))
	for _, assessmentID := range ids {
		subject := ports.AssessmentCycleIntegritySubject{TenantID: tenantID, AssessmentID: assessmentID}
		cycleID := repository.cycles.assessmentToCycle[tenantID][assessmentID]
		if !cycleID.IsZero() {
			cycle := repository.cycles.cycles[tenantID][cycleID]
			if cycle != nil {
				record := ports.AssessmentCycleIntegrityCycle{Cycle: *cloneCycle(cycle), CycleExists: true, SubjectMembershipCount: 1}
				for _, member := range repository.cycles.members[tenantID][cycleID] {
					wrapped := ports.AssessmentCycleIntegrityMember{Member: *cloneMember(member)}
					if engagement := repository.engagements.data[member.AssessmentID]; engagement != nil {
						wrapped.AssessmentExists = true
						wrapped.AssessmentStatus, wrapped.BusinessAssetID, wrapped.ProjectID = engagement.Status, engagement.BusinessAssetID, engagement.ProjectID
					}
					record.Members = append(record.Members, wrapped)
				}
				sort.Slice(record.Members, func(left, right int) bool {
					leftMember, rightMember := record.Members[left].Member, record.Members[right].Member
					if leftMember.RetestNumber == rightMember.RetestNumber {
						return leftMember.AssessmentID < rightMember.AssessmentID
					}
					return leftMember.RetestNumber < rightMember.RetestNumber
				})
				subject.Cycles = append(subject.Cycles, record)
			}
		}
		subjects = append(subjects, subject)
	}
	return subjects, nil
}

func (repository *AssessmentCycleIntegrityRepository) CountAssessmentCycleIntegritySubjects(_ context.Context, tenantID shared.ID, snapshotAt time.Time) (eligible int, memberships int, err error) {
	if repository.engagements == nil || repository.cycles == nil || snapshotAt.IsZero() {
		return 0, 0, fmt.Errorf("%w: assessment cycle integrity count is invalid", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.engagements.mu.RLock()
	repository.cycles.mu.Lock()
	defer repository.engagements.mu.RUnlock()
	defer repository.cycles.mu.Unlock()
	for assessmentID, engagement := range repository.engagements.data {
		if engagement.TenantID != tenantID || !engagement.ProjectID.IsZero() || engagement.Audit.CreatedAt.After(snapshotAt) {
			continue
		}
		eligible++
		if !repository.cycles.assessmentToCycle[tenantID][assessmentID].IsZero() {
			memberships++
		}
	}
	return eligible, memberships, nil
}

func (repository *AssessmentCycleIntegrityRepository) AcquireAssessmentCycleIntegrityRun(_ context.Context, request ports.AssessmentCycleIntegrityAcquireRequest) (ports.AssessmentCycleIntegrityRun, bool, error) {
	if err := validateIntegrityAcquire(request); err != nil {
		return ports.AssessmentCycleIntegrityRun{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantRuns := repository.runs[request.Run.TenantID]
	if tenantRuns == nil {
		tenantRuns = map[shared.ID]ports.AssessmentCycleIntegrityRun{}
		repository.runs[request.Run.TenantID] = tenantRuns
	}
	for id, run := range tenantRuns {
		if run.State != ports.AssessmentCycleIntegrityRunning {
			continue
		}
		if run.LeaseOwner != request.Run.LeaseOwner && run.LeaseExpiresAt.After(request.Run.CreatedAt) {
			return ports.AssessmentCycleIntegrityRun{}, false, fmt.Errorf("%w: assessment cycle integrity verifier already running for tenant", shared.ErrConflict)
		}
		run.LeaseOwner, run.LeaseExpiresAt, run.UpdatedAt = request.Run.LeaseOwner, request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedAt
		tenantRuns[id] = run
		return cloneIntegrityRun(run), true, nil
	}
	tenantRuns[request.Run.ID] = request.Run
	return cloneIntegrityRun(request.Run), false, nil
}

func (repository *AssessmentCycleIntegrityRepository) GetAssessmentCycleIntegrityRun(_ context.Context, tenantID, runID shared.ID) (ports.AssessmentCycleIntegrityRun, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run, ok := repository.runs[shared.TenantOrDefault(tenantID)][runID]
	if !ok {
		return ports.AssessmentCycleIntegrityRun{}, shared.ErrNotFound
	}
	return cloneIntegrityRun(run), nil
}

func (repository *AssessmentCycleIntegrityRepository) GetAssessmentCycleIntegritySubject(_ context.Context, tenantID, runID, assessmentID shared.ID) (ports.AssessmentCycleIntegritySubjectResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	result, ok := repository.subjects[shared.TenantOrDefault(tenantID)][runID][assessmentID]
	if !ok {
		return ports.AssessmentCycleIntegritySubjectResult{}, shared.ErrNotFound
	}
	return result, nil
}

func (repository *AssessmentCycleIntegrityRepository) ListAssessmentCycleIntegrityFindings(_ context.Context, tenantID, runID shared.ID) ([]ports.AssessmentCycleIntegrityFinding, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	items := repository.findings[shared.TenantOrDefault(tenantID)][runID]
	findings := make([]ports.AssessmentCycleIntegrityFinding, 0, len(items))
	for _, finding := range items {
		finding.RepairPlan = append([]byte(nil), finding.RepairPlan...)
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(left, right int) bool { return findings[left].OccurrenceID < findings[right].OccurrenceID })
	return findings, nil
}

func (repository *AssessmentCycleIntegrityRepository) SaveAssessmentCycleIntegritySubject(_ context.Context, result ports.AssessmentCycleIntegritySubjectResult, findings []ports.AssessmentCycleIntegrityFinding) (bool, error) {
	if err := validateIntegritySubject(result, findings); err != nil {
		return false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run, ok := repository.runs[result.TenantID][result.RunID]
	if !ok {
		return false, shared.ErrNotFound
	}
	if run.State != ports.AssessmentCycleIntegrityRunning {
		return false, fmt.Errorf("%w: assessment cycle integrity run is not active", shared.ErrConflict)
	}
	tenantSubjects := repository.subjects[result.TenantID]
	if tenantSubjects == nil {
		tenantSubjects = map[shared.ID]map[shared.ID]ports.AssessmentCycleIntegritySubjectResult{}
		repository.subjects[result.TenantID] = tenantSubjects
	}
	runSubjects := tenantSubjects[result.RunID]
	if runSubjects == nil {
		runSubjects = map[shared.ID]ports.AssessmentCycleIntegritySubjectResult{}
		tenantSubjects[result.RunID] = runSubjects
	}
	if _, exists := runSubjects[result.AssessmentID]; exists {
		return false, nil
	}
	runSubjects[result.AssessmentID] = result
	tenantFindings := repository.findings[result.TenantID]
	if tenantFindings == nil {
		tenantFindings = map[shared.ID]map[string]ports.AssessmentCycleIntegrityFinding{}
		repository.findings[result.TenantID] = tenantFindings
	}
	runFindings := tenantFindings[result.RunID]
	if runFindings == nil {
		runFindings = map[string]ports.AssessmentCycleIntegrityFinding{}
		tenantFindings[result.RunID] = runFindings
	}
	for _, finding := range findings {
		finding.RepairPlan = append([]byte(nil), finding.RepairPlan...)
		runFindings[finding.OccurrenceID] = finding
	}
	return true, nil
}

func (repository *AssessmentCycleIntegrityRepository) AdvanceAssessmentCycleIntegrityRun(_ context.Context, tenantID, runID shared.ID, leaseOwner string, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (ports.AssessmentCycleIntegrityRun, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.AssessmentCycleIntegrityRun{}, shared.ErrNotFound
	}
	if run.State != ports.AssessmentCycleIntegrityRunning || run.LeaseOwner != strings.TrimSpace(leaseOwner) || checkpoint < run.CheckpointAssessment || leaseDuration <= 0 {
		return ports.AssessmentCycleIntegrityRun{}, fmt.Errorf("%w: assessment cycle integrity checkpoint rejected", shared.ErrConflict)
	}
	run.CheckpointAssessment, run.UpdatedAt, run.LeaseExpiresAt = checkpoint, now.UTC(), now.UTC().Add(leaseDuration)
	recomputeIntegrityCounts(&run, repository.subjects[tenantID][runID])
	repository.runs[tenantID][runID] = run
	return cloneIntegrityRun(run), nil
}

func (repository *AssessmentCycleIntegrityRepository) FinishAssessmentCycleIntegrityRun(_ context.Context, tenantID, runID shared.ID, leaseOwner string, state ports.AssessmentCycleIntegrityState, now time.Time) (ports.AssessmentCycleIntegrityRun, error) {
	if state != ports.AssessmentCycleIntegrityCompleted && state != ports.AssessmentCycleIntegrityCancelled && state != ports.AssessmentCycleIntegrityFailed {
		return ports.AssessmentCycleIntegrityRun{}, fmt.Errorf("%w: invalid assessment cycle integrity terminal state", shared.ErrValidation)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.AssessmentCycleIntegrityRun{}, shared.ErrNotFound
	}
	if run.State != ports.AssessmentCycleIntegrityRunning || run.LeaseOwner != strings.TrimSpace(leaseOwner) {
		return ports.AssessmentCycleIntegrityRun{}, fmt.Errorf("%w: assessment cycle integrity completion rejected", shared.ErrConflict)
	}
	completedAt := now.UTC()
	run.State, run.UpdatedAt, run.CompletedAt = state, completedAt, &completedAt
	run.LeaseOwner, run.LeaseExpiresAt = "", time.Time{}
	recomputeIntegrityCounts(&run, repository.subjects[tenantID][runID])
	repository.runs[tenantID][runID] = run
	return cloneIntegrityRun(run), nil
}

func validateIntegrityAcquire(request ports.AssessmentCycleIntegrityAcquireRequest) error {
	run := request.Run
	if run.TenantID.IsZero() || run.ID.IsZero() || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.State != ports.AssessmentCycleIntegrityRunning || strings.TrimSpace(run.LeaseOwner) == "" || len(run.LeaseOwner) > 256 || strings.TrimSpace(run.CreatedBy) == "" || len(run.CreatedBy) > 256 || run.CreatedAt.IsZero() || request.LeaseDuration <= 0 {
		return fmt.Errorf("%w: assessment cycle integrity run is invalid", shared.ErrValidation)
	}
	return nil
}

func validateIntegritySubject(result ports.AssessmentCycleIntegritySubjectResult, findings []ports.AssessmentCycleIntegrityFinding) error {
	if result.TenantID.IsZero() || result.RunID.IsZero() || result.AssessmentID.IsZero() || result.FindingCount != len(findings) || result.Clean != (len(findings) == 0) || result.ProcessedAt.IsZero() {
		return fmt.Errorf("%w: assessment cycle integrity subject result is invalid", shared.ErrValidation)
	}
	for _, finding := range findings {
		validSeverity := finding.Severity == "medium" || finding.Severity == "high" || finding.Severity == "critical"
		if finding.TenantID != result.TenantID || finding.RunID != result.RunID || finding.AssessmentID != result.AssessmentID || strings.TrimSpace(finding.OccurrenceID) == "" || len(finding.OccurrenceID) > 64 || strings.TrimSpace(finding.ReasonCode) == "" || len(finding.ReasonCode) > 64 || !validSeverity || len(finding.RepairPlan) == 0 || len(finding.RepairPlan) > 8192 || finding.DetectedAt.IsZero() {
			return fmt.Errorf("%w: assessment cycle integrity finding is invalid", shared.ErrValidation)
		}
	}
	return nil
}

func recomputeIntegrityCounts(run *ports.AssessmentCycleIntegrityRun, subjects map[shared.ID]ports.AssessmentCycleIntegritySubjectResult) {
	run.ScannedCount, run.CleanCount, run.FindingCount = 0, 0, 0
	for _, subject := range subjects {
		run.ScannedCount++
		if subject.Clean {
			run.CleanCount++
		}
		run.FindingCount += subject.FindingCount
	}
}

func cloneIntegrityRun(run ports.AssessmentCycleIntegrityRun) ports.AssessmentCycleIntegrityRun {
	if run.CompletedAt != nil {
		completedAt := *run.CompletedAt
		run.CompletedAt = &completedAt
	}
	return run
}
