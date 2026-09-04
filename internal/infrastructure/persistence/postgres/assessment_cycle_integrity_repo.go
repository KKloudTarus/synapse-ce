package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const assessmentCycleIntegrityRunCols = `tenant_id,id,batch_size,snapshot_at,checkpoint_assessment_id,state,lease_owner,lease_token,lease_expires_at,scanned_count,clean_count,finding_count,created_by,created_at,updated_at,completed_at`

type AssessmentCycleIntegrityRepository struct{ pool *pgxpool.Pool }

func NewAssessmentCycleIntegrityRepository(pool *pgxpool.Pool) *AssessmentCycleIntegrityRepository {
	return &AssessmentCycleIntegrityRepository{pool: pool}
}

var _ ports.AssessmentCycleIntegritySource = (*AssessmentCycleIntegrityRepository)(nil)
var _ ports.AssessmentCycleIntegrityStore = (*AssessmentCycleIntegrityRepository)(nil)

func (repository *AssessmentCycleIntegrityRepository) ListAssessmentCycleIntegritySubjects(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, limit int) (subjects []ports.AssessmentCycleIntegritySubject, err error) {
	if snapshotAt.IsZero() || limit < 1 || limit > 2000 {
		return nil, fmt.Errorf("%w: assessment cycle integrity page is invalid", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM engagements WHERE tenant_id=$1 AND project_id IS NULL AND id COLLATE "C">$2 AND created_at<=$3 ORDER BY id COLLATE "C" LIMIT $4`, tenantID.String(), after.String(), snapshotAt.UTC(), limit)
		if err != nil {
			return fmt.Errorf("list assessment cycle integrity subjects: %w", err)
		}
		assessmentIDs := make([]shared.ID, 0, limit)
		for rows.Next() {
			var assessmentID shared.ID
			if err := rows.Scan(&assessmentID); err != nil {
				rows.Close()
				return fmt.Errorf("scan assessment cycle integrity subject: %w", err)
			}
			assessmentIDs = append(assessmentIDs, assessmentID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(assessmentIDs) == 0 {
			return nil
		}
		idStrings := make([]string, len(assessmentIDs))
		subjectIndex := make(map[shared.ID]int, len(assessmentIDs))
		for index, assessmentID := range assessmentIDs {
			idStrings[index] = assessmentID.String()
			subjects = append(subjects, ports.AssessmentCycleIntegritySubject{TenantID: tenantID, AssessmentID: assessmentID})
			subjectIndex[assessmentID] = len(subjects) - 1
		}
		membershipRows, err := tx.Query(ctx, `SELECT assessment_id,cycle_id,count(*) FROM assessment_cycle_members WHERE tenant_id=$1 AND assessment_id=ANY($2) GROUP BY assessment_id,cycle_id ORDER BY assessment_id,cycle_id`, tenantID.String(), idStrings)
		if err != nil {
			return fmt.Errorf("list assessment cycle integrity memberships: %w", err)
		}
		membershipCounts := map[shared.ID]map[shared.ID]int{}
		cycleSet := map[shared.ID]bool{}
		for membershipRows.Next() {
			var assessmentID, cycleID shared.ID
			var count int
			if err := membershipRows.Scan(&assessmentID, &cycleID, &count); err != nil {
				membershipRows.Close()
				return err
			}
			if membershipCounts[assessmentID] == nil {
				membershipCounts[assessmentID] = map[shared.ID]int{}
			}
			membershipCounts[assessmentID][cycleID] = count
			cycleSet[cycleID] = true
		}
		if err := membershipRows.Err(); err != nil {
			membershipRows.Close()
			return err
		}
		membershipRows.Close()
		if len(cycleSet) == 0 {
			return nil
		}
		cycleIDs := make([]string, 0, len(cycleSet))
		for cycleID := range cycleSet {
			cycleIDs = append(cycleIDs, cycleID.String())
		}
		cycleRows, err := tx.Query(ctx, `SELECT `+assessmentCycleCols+` FROM assessment_cycles WHERE tenant_id=$1 AND id=ANY($2)`, tenantID.String(), cycleIDs)
		if err != nil {
			return fmt.Errorf("load assessment cycles for integrity: %w", err)
		}
		cycles := map[shared.ID]cycledom.AssessmentCycle{}
		for cycleRows.Next() {
			cycle, err := scanAssessmentCycle(cycleRows)
			if err != nil {
				cycleRows.Close()
				return err
			}
			cycles[cycle.ID] = *cycle
		}
		if err := cycleRows.Err(); err != nil {
			cycleRows.Close()
			return err
		}
		cycleRows.Close()
		memberRows, err := tx.Query(ctx, `SELECT m.tenant_id,m.cycle_id,m.assessment_id,m.assessment_type,COALESCE(m.predecessor_assessment_id,''),m.retest_number,m.relationship_version,m.created_at,m.created_by,m.archived_at,
			e.id IS NOT NULL,COALESCE(e.status,''),COALESCE(e.business_asset_id,''),COALESCE(e.project_id,'')
			FROM assessment_cycle_members m LEFT JOIN engagements e ON e.tenant_id=m.tenant_id AND e.id=m.assessment_id
			WHERE m.tenant_id=$1 AND m.cycle_id=ANY($2) ORDER BY m.cycle_id,m.retest_number,m.assessment_id`, tenantID.String(), cycleIDs)
		if err != nil {
			return fmt.Errorf("load assessment cycle integrity members: %w", err)
		}
		members := map[shared.ID][]ports.AssessmentCycleIntegrityMember{}
		for memberRows.Next() {
			var (
				wrapped   ports.AssessmentCycleIntegrityMember
				typeValue string
				status    string
				archived  pgtype.Timestamptz
			)
			if err := memberRows.Scan(&wrapped.Member.TenantID, &wrapped.Member.CycleID, &wrapped.Member.AssessmentID, &typeValue, &wrapped.Member.PredecessorAssessmentID,
				&wrapped.Member.RetestNumber, &wrapped.Member.RelationshipVersion, &wrapped.Member.CreatedAt, &wrapped.Member.CreatedBy, &archived,
				&wrapped.AssessmentExists, &status, &wrapped.BusinessAssetID, &wrapped.ProjectID); err != nil {
				memberRows.Close()
				return err
			}
			wrapped.Member.AssessmentType, wrapped.AssessmentStatus = cycledom.AssessmentType(typeValue), engdom.Status(status)
			if archived.Valid {
				archivedAt := archived.Time
				wrapped.Member.ArchivedAt = &archivedAt
			}
			members[wrapped.Member.CycleID] = append(members[wrapped.Member.CycleID], wrapped)
		}
		if err := memberRows.Err(); err != nil {
			memberRows.Close()
			return err
		}
		memberRows.Close()
		for assessmentID, cycleMemberships := range membershipCounts {
			subject := &subjects[subjectIndex[assessmentID]]
			for cycleID, count := range cycleMemberships {
				cycle, exists := cycles[cycleID]
				if !exists {
					cycle = cycledom.AssessmentCycle{TenantID: tenantID, ID: cycleID}
				}
				subject.Cycles = append(subject.Cycles, ports.AssessmentCycleIntegrityCycle{Cycle: cycle, CycleExists: exists, SubjectMembershipCount: count, Members: append([]ports.AssessmentCycleIntegrityMember(nil), members[cycleID]...)})
			}
			sort.Slice(subject.Cycles, func(left, right int) bool { return subject.Cycles[left].Cycle.ID < subject.Cycles[right].Cycle.ID })
		}
		return nil
	})
	return subjects, err
}

func (repository *AssessmentCycleIntegrityRepository) CountAssessmentCycleIntegritySubjects(ctx context.Context, tenantID shared.ID, snapshotAt time.Time) (eligible int, memberships int, err error) {
	if snapshotAt.IsZero() {
		return 0, 0, fmt.Errorf("%w: assessment cycle integrity count snapshot is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM engagements WHERE tenant_id=$1 AND project_id IS NULL AND created_at<=$2`, tenantID.String(), snapshotAt.UTC()).Scan(&eligible); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM assessment_cycle_members member JOIN engagements assessment ON assessment.tenant_id=member.tenant_id AND assessment.id=member.assessment_id
			WHERE member.tenant_id=$1 AND assessment.project_id IS NULL AND assessment.created_at<=$2`, tenantID.String(), snapshotAt.UTC()).Scan(&memberships)
	})
	return eligible, memberships, err
}

func (repository *AssessmentCycleIntegrityRepository) AcquireAssessmentCycleIntegrityRun(ctx context.Context, request ports.AssessmentCycleIntegrityAcquireRequest) (run ports.AssessmentCycleIntegrityRun, resumed bool, err error) {
	if err := validatePostgresIntegrityAcquire(request); err != nil {
		return ports.AssessmentCycleIntegrityRun{}, false, err
	}
	err = WithTenant(ctx, repository.pool, request.Run.TenantID.String(), func(tx pgx.Tx) error {
		existing, scanErr := scanAssessmentCycleIntegrityRun(tx.QueryRow(ctx, `SELECT `+assessmentCycleIntegrityRunCols+` FROM assessment_cycle_integrity_runs WHERE tenant_id=$1 AND state='running' FOR UPDATE`, request.Run.TenantID.String()))
		if scanErr == nil {
			if existing.LeaseOwner != request.Run.LeaseOwner && existing.LeaseExpiresAt.After(request.Run.CreatedAt) {
				return fmt.Errorf("%w: assessment cycle integrity verifier already running for tenant", shared.ErrConflict)
			}
			if existing.BatchSize != request.Run.BatchSize {
				return fmt.Errorf("%w: requested assessment cycle integrity batch size %d differs from persisted batch size %d", shared.ErrConflict, request.Run.BatchSize, existing.BatchSize)
			}
			updated, err := scanAssessmentCycleIntegrityRun(tx.QueryRow(ctx, `UPDATE assessment_cycle_integrity_runs SET lease_owner=$3,lease_token=$4,lease_expires_at=$5,updated_at=$6 WHERE tenant_id=$1 AND id=$2 AND state='running' RETURNING `+assessmentCycleIntegrityRunCols,
				request.Run.TenantID.String(), existing.ID.String(), request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedAt))
			if err != nil {
				return fmt.Errorf("resume assessment cycle integrity run: %w", err)
			}
			run, resumed = updated, true
			return nil
		}
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return fmt.Errorf("find active assessment cycle integrity run: %w", scanErr)
		}
		created, err := scanAssessmentCycleIntegrityRun(tx.QueryRow(ctx, `INSERT INTO assessment_cycle_integrity_runs (`+assessmentCycleIntegrityRunCols+`) VALUES ($1,$2,$3,$4,'','running',$5,$6,$7,0,0,0,$8,$9,$9,NULL) RETURNING `+assessmentCycleIntegrityRunCols,
			request.Run.TenantID.String(), request.Run.ID.String(), request.Run.BatchSize, request.Run.SnapshotAt, request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedBy, request.Run.CreatedAt))
		if err != nil {
			return fmt.Errorf("create assessment cycle integrity run: %w", err)
		}
		run = created
		return nil
	})
	return run, resumed, err
}

func (repository *AssessmentCycleIntegrityRepository) GetAssessmentCycleIntegrityRun(ctx context.Context, tenantID, runID shared.ID) (run ports.AssessmentCycleIntegrityRun, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		item, err := scanAssessmentCycleIntegrityRun(tx.QueryRow(ctx, `SELECT `+assessmentCycleIntegrityRunCols+` FROM assessment_cycle_integrity_runs WHERE tenant_id=$1 AND id=$2`, tenantID.String(), runID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		run = item
		return nil
	})
	return run, err
}

func (repository *AssessmentCycleIntegrityRepository) GetAssessmentCycleIntegritySubject(ctx context.Context, tenantID, runID, assessmentID shared.ID) (result ports.AssessmentCycleIntegritySubjectResult, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT tenant_id,run_id,assessment_id,clean,finding_count,processed_at FROM assessment_cycle_integrity_subjects WHERE tenant_id=$1 AND run_id=$2 AND assessment_id=$3`, tenantID.String(), runID.String(), assessmentID.String()).Scan(
			&result.TenantID, &result.RunID, &result.AssessmentID, &result.Clean, &result.FindingCount, &result.ProcessedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return err
	})
	return result, err
}

func (repository *AssessmentCycleIntegrityRepository) ListAssessmentCycleIntegrityFindings(ctx context.Context, tenantID, runID shared.ID) (findings []ports.AssessmentCycleIntegrityFinding, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,run_id,occurrence_id,assessment_id,COALESCE(cycle_id,''),COALESCE(member_id,''),reason_code,severity,repair_plan,detected_at FROM assessment_cycle_integrity_findings WHERE tenant_id=$1 AND run_id=$2 ORDER BY occurrence_id`, tenantID.String(), runID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var finding ports.AssessmentCycleIntegrityFinding
			if err := rows.Scan(&finding.TenantID, &finding.RunID, &finding.OccurrenceID, &finding.AssessmentID, &finding.CycleID, &finding.MemberID, &finding.ReasonCode, &finding.Severity, &finding.RepairPlan, &finding.DetectedAt); err != nil {
				return err
			}
			findings = append(findings, finding)
		}
		return rows.Err()
	})
	return findings, err
}

func (repository *AssessmentCycleIntegrityRepository) SaveAssessmentCycleIntegritySubject(ctx context.Context, leaseToken shared.ID, now time.Time, result ports.AssessmentCycleIntegritySubjectResult, findings []ports.AssessmentCycleIntegrityFinding) (created bool, err error) {
	if err := validatePostgresIntegritySubject(result, findings); err != nil {
		return false, err
	}
	if leaseToken.IsZero() || now.IsZero() {
		return false, fmt.Errorf("%w: assessment cycle integrity lease identity is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, result.TenantID.String(), func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT state='running' AND lease_token=$3 AND lease_expires_at>$4 FROM assessment_cycle_integrity_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, result.TenantID.String(), result.RunID.String(), leaseToken.String(), now.UTC()).Scan(&active); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("lock assessment cycle integrity lease: %w", err)
		}
		if !active {
			return fmt.Errorf("%w: assessment cycle integrity lease is stale", shared.ErrConflict)
		}
		var inserted int
		err := tx.QueryRow(ctx, `INSERT INTO assessment_cycle_integrity_subjects(tenant_id,run_id,assessment_id,clean,finding_count,processed_at) VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT (tenant_id,run_id,assessment_id) DO NOTHING RETURNING 1`, result.TenantID.String(), result.RunID.String(), result.AssessmentID.String(), result.Clean, result.FindingCount, result.ProcessedAt.UTC()).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("save assessment cycle integrity subject: %w", err)
		}
		for _, finding := range findings {
			if _, err := tx.Exec(ctx, `INSERT INTO assessment_cycle_integrity_findings(tenant_id,run_id,occurrence_id,assessment_id,cycle_id,member_id,reason_code,severity,repair_plan,detected_at)
				VALUES($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10)`, finding.TenantID.String(), finding.RunID.String(), finding.OccurrenceID, finding.AssessmentID.String(), finding.CycleID.String(), finding.MemberID.String(), finding.ReasonCode, finding.Severity, finding.RepairPlan, finding.DetectedAt.UTC()); err != nil {
				return fmt.Errorf("save assessment cycle integrity finding: %w", err)
			}
		}
		created = inserted == 1
		return nil
	})
	return created, err
}

func (repository *AssessmentCycleIntegrityRepository) AdvanceAssessmentCycleIntegrityRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (run ports.AssessmentCycleIntegrityRun, err error) {
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseOwner == "" || leaseToken.IsZero() || checkpoint.IsZero() || now.IsZero() || leaseDuration <= 0 {
		return ports.AssessmentCycleIntegrityRun{}, fmt.Errorf("%w: assessment cycle integrity checkpoint is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		updated, err := scanAssessmentCycleIntegrityRun(tx.QueryRow(ctx, `UPDATE assessment_cycle_integrity_runs AS run SET checkpoint_assessment_id=$5,updated_at=$6::timestamptz,lease_expires_at=$6::timestamptz+($7 * interval '1 microsecond'),
			scanned_count=(SELECT count(*) FROM assessment_cycle_integrity_subjects subject WHERE subject.tenant_id=run.tenant_id AND subject.run_id=run.id),
			clean_count=(SELECT count(*) FROM assessment_cycle_integrity_subjects subject WHERE subject.tenant_id=run.tenant_id AND subject.run_id=run.id AND subject.clean),
			finding_count=(SELECT COALESCE(sum(subject.finding_count),0) FROM assessment_cycle_integrity_subjects subject WHERE subject.tenant_id=run.tenant_id AND subject.run_id=run.id)
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>$6 AND run.checkpoint_assessment_id COLLATE "C"<=$5 RETURNING `+assessmentCycleIntegrityRunCols,
			tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), checkpoint.String(), now, leaseDuration.Microseconds()))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: assessment cycle integrity checkpoint rejected", shared.ErrConflict)
		}
		if err != nil {
			return err
		}
		run = updated
		return nil
	})
	return run, err
}

func (repository *AssessmentCycleIntegrityRepository) FinishAssessmentCycleIntegrityRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state ports.AssessmentCycleIntegrityState, now time.Time) (run ports.AssessmentCycleIntegrityRun, err error) {
	if state != ports.AssessmentCycleIntegrityCompleted && state != ports.AssessmentCycleIntegrityCancelled && state != ports.AssessmentCycleIntegrityFailed {
		return ports.AssessmentCycleIntegrityRun{}, fmt.Errorf("%w: invalid assessment cycle integrity terminal state", shared.ErrValidation)
	}
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseOwner == "" || leaseToken.IsZero() || now.IsZero() {
		return ports.AssessmentCycleIntegrityRun{}, fmt.Errorf("%w: assessment cycle integrity completion identity is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		finished, err := scanAssessmentCycleIntegrityRun(tx.QueryRow(ctx, `UPDATE assessment_cycle_integrity_runs AS run SET state=$5,lease_owner='',lease_token='',lease_expires_at=NULL,updated_at=$6,completed_at=$6,
			scanned_count=(SELECT count(*) FROM assessment_cycle_integrity_subjects subject WHERE subject.tenant_id=run.tenant_id AND subject.run_id=run.id),
			clean_count=(SELECT count(*) FROM assessment_cycle_integrity_subjects subject WHERE subject.tenant_id=run.tenant_id AND subject.run_id=run.id AND subject.clean),
			finding_count=(SELECT COALESCE(sum(subject.finding_count),0) FROM assessment_cycle_integrity_subjects subject WHERE subject.tenant_id=run.tenant_id AND subject.run_id=run.id)
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>$6 RETURNING `+assessmentCycleIntegrityRunCols,
			tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), string(state), now))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: assessment cycle integrity completion rejected", shared.ErrConflict)
		}
		if err != nil {
			return err
		}
		run = finished
		return nil
	})
	return run, err
}

func scanAssessmentCycleIntegrityRun(row rowScanner) (ports.AssessmentCycleIntegrityRun, error) {
	var (
		run                       ports.AssessmentCycleIntegrityRun
		state                     string
		leaseExpires, completedAt pgtype.Timestamptz
	)
	if err := row.Scan(&run.TenantID, &run.ID, &run.BatchSize, &run.SnapshotAt, &run.CheckpointAssessment, &state, &run.LeaseOwner, &run.LeaseToken, &leaseExpires,
		&run.ScannedCount, &run.CleanCount, &run.FindingCount, &run.CreatedBy, &run.CreatedAt, &run.UpdatedAt, &completedAt); err != nil {
		return ports.AssessmentCycleIntegrityRun{}, err
	}
	run.State = ports.AssessmentCycleIntegrityState(state)
	if leaseExpires.Valid {
		run.LeaseExpiresAt = leaseExpires.Time
	}
	if completedAt.Valid {
		completed := completedAt.Time
		run.CompletedAt = &completed
	}
	return run, nil
}

func validatePostgresIntegrityAcquire(request ports.AssessmentCycleIntegrityAcquireRequest) error {
	run := request.Run
	if run.TenantID.IsZero() || run.ID.IsZero() || run.LeaseToken.IsZero() || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.State != ports.AssessmentCycleIntegrityRunning || strings.TrimSpace(run.LeaseOwner) == "" || len(run.LeaseOwner) > 256 || strings.TrimSpace(run.CreatedBy) == "" || len(run.CreatedBy) > 256 || run.CreatedAt.IsZero() || request.LeaseDuration <= 0 {
		return fmt.Errorf("%w: assessment cycle integrity run is invalid", shared.ErrValidation)
	}
	return nil
}

func validatePostgresIntegritySubject(result ports.AssessmentCycleIntegritySubjectResult, findings []ports.AssessmentCycleIntegrityFinding) error {
	if result.TenantID.IsZero() || result.RunID.IsZero() || result.AssessmentID.IsZero() || result.FindingCount != len(findings) || result.Clean != (len(findings) == 0) || result.ProcessedAt.IsZero() {
		return fmt.Errorf("%w: assessment cycle integrity subject result is invalid", shared.ErrValidation)
	}
	for _, finding := range findings {
		validSeverity := finding.Severity == "medium" || finding.Severity == "high" || finding.Severity == "critical"
		if finding.TenantID != result.TenantID || finding.RunID != result.RunID || finding.AssessmentID != result.AssessmentID || len(finding.OccurrenceID) != 32 || strings.TrimSpace(finding.ReasonCode) == "" || len(finding.ReasonCode) > 64 || !validSeverity || !json.Valid(finding.RepairPlan) || len(finding.RepairPlan) > 8192 || finding.DetectedAt.IsZero() {
			return fmt.Errorf("%w: assessment cycle integrity finding is invalid", shared.ErrValidation)
		}
	}
	return nil
}
