package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentrelationship"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const assessmentRelationshipCandidateColumns = `tenant_id,id,predecessor_cycle_id,predecessor_assessment_id,
	predecessor_relationship_version,predecessor_snapshot_id,predecessor_snapshot_hash,successor_cycle_id,
	successor_assessment_id,successor_relationship_version,successor_snapshot_id,successor_snapshot_hash,
	boundary_key_hash,signals,input_hash,confidence,expires_at,created_by,created_at`

type AssessmentRelationshipRepository struct{ pool *pgxpool.Pool }

func NewAssessmentRelationshipRepository(pool *pgxpool.Pool) *AssessmentRelationshipRepository {
	return &AssessmentRelationshipRepository{pool: pool}
}

var _ ports.AssessmentRelationshipRepository = (*AssessmentRelationshipRepository)(nil)

func (repository *AssessmentRelationshipRepository) CreateCandidate(ctx context.Context, candidate assessmentrelationship.Candidate) (record assessmentrelationship.Record, created bool, err error) {
	candidate.TenantID = shared.TenantOrDefault(candidate.TenantID)
	if err := candidate.Validate(); err != nil {
		return assessmentrelationship.Record{}, false, err
	}
	signals, err := json.Marshal(candidate.Signals)
	if err != nil {
		return assessmentrelationship.Record{}, false, fmt.Errorf("marshal relationship candidate signals: %w", err)
	}
	err = WithTenant(ctx, repository.pool, candidate.TenantID.String(), func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `INSERT INTO assessment_relationship_candidates(`+assessmentRelationshipCandidateColumns+`)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
			ON CONFLICT (tenant_id,input_hash) DO NOTHING`,
			candidate.TenantID.String(), candidate.ID.String(), candidate.PredecessorCycleID.String(), candidate.PredecessorAssessmentID.String(),
			candidate.PredecessorRelationshipVersion, candidate.PredecessorSnapshotID.String(), candidate.PredecessorSnapshotHash,
			candidate.SuccessorCycleID.String(), candidate.SuccessorAssessmentID.String(), candidate.SuccessorRelationshipVersion,
			candidate.SuccessorSnapshotID.String(), candidate.SuccessorSnapshotHash, candidate.BoundaryKeyHash, signals,
			candidate.InputHash, string(candidate.Confidence), candidate.ExpiresAt, candidate.CreatedBy, candidate.CreatedAt)
		if err != nil {
			return mapPostgresError(err, "create assessment relationship candidate")
		}
		created = result.RowsAffected() == 1
		candidateID := candidate.ID
		if !created {
			if err := tx.QueryRow(ctx, `SELECT id FROM assessment_relationship_candidates WHERE tenant_id=$1 AND input_hash=$2`, candidate.TenantID.String(), candidate.InputHash).Scan(&candidateID); err != nil {
				return err
			}
		}
		record, err = loadAssessmentRelationshipRecord(ctx, tx, candidate.TenantID, candidateID, false)
		return err
	})
	return record, created, err
}

func (repository *AssessmentRelationshipRepository) GetCandidate(ctx context.Context, tenantID, candidateID shared.ID) (record assessmentrelationship.Record, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		record, err = loadAssessmentRelationshipRecord(ctx, tx, tenantID, candidateID, false)
		return err
	})
	return record, err
}

func (repository *AssessmentRelationshipRepository) ListCandidates(ctx context.Context, tenantID shared.ID, filter ports.AssessmentRelationshipCandidateFilter) (records []assessmentrelationship.Record, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if filter.Limit < 1 || filter.Limit > 200 {
		return nil, fmt.Errorf("%w: relationship candidate page is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM assessment_relationship_candidates
			WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2`, tenantID.String(), filter.Limit)
		if err != nil {
			return fmt.Errorf("list assessment relationship candidate ids: %w", err)
		}
		var ids []shared.ID
		for rows.Next() {
			var id shared.ID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, id := range ids {
			record, err := loadAssessmentRelationshipRecord(ctx, tx, tenantID, id, false)
			if err != nil {
				return err
			}
			records = append(records, record)
		}
		return nil
	})
	return records, err
}

func (repository *AssessmentRelationshipRepository) DecideCandidateCAS(ctx context.Context, decision assessmentrelationship.Decision, plan *assessmentrelationship.RepairPlan) (record assessmentrelationship.Record, replayed bool, err error) {
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
	err = WithTenant(ctx, repository.pool, decision.TenantID.String(), func(tx pgx.Tx) error {
		var existingHash string
		err := tx.QueryRow(ctx, `SELECT request_hash FROM assessment_relationship_decisions
			WHERE tenant_id=$1 AND candidate_id=$2 AND actor=$3 AND idempotency_key=$4`,
			decision.TenantID.String(), decision.CandidateID.String(), decision.Actor, decision.IdempotencyKey).Scan(&existingHash)
		if err == nil {
			if existingHash != decision.RequestHash {
				return fmt.Errorf("%w: idempotency key was reused with different content", shared.ErrConflict)
			}
			replayed = true
			record, err = loadAssessmentRelationshipRecord(ctx, tx, decision.TenantID, decision.CandidateID, false)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var expiresAt time.Time
		if err := tx.QueryRow(ctx, `SELECT expires_at FROM assessment_relationship_candidates
			WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, decision.TenantID.String(), decision.CandidateID.String()).Scan(&expiresAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assessment_relationship_decisions WHERE tenant_id=$1 AND candidate_id=$2)`, decision.TenantID.String(), decision.CandidateID.String()).Scan(&exists); err != nil {
			return err
		}
		if exists || decision.ExpectedVersion != 1 {
			return fmt.Errorf("%w: relationship candidate version mismatch", shared.ErrConflict)
		}
		if !expiresAt.After(decision.CreatedAt) {
			return fmt.Errorf("%w: relationship candidate expired", shared.ErrConflict)
		}
		if plan != nil {
			if plan.TenantID != decision.TenantID || plan.CandidateID != decision.CandidateID || plan.ID != decision.RepairPlanID {
				return fmt.Errorf("%w: relationship repair plan ownership is invalid", shared.ErrValidation)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO assessment_relationship_repair_plans(
				tenant_id,id,candidate_id,input_hash,plan_hash,body,created_by,created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, plan.TenantID.String(), plan.ID.String(), plan.CandidateID.String(),
				plan.InputHash, plan.PlanHash, plan.Body, plan.CreatedBy, plan.CreatedAt); err != nil {
				return mapPostgresError(err, "create assessment relationship repair plan")
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_relationship_decisions(
			tenant_id,id,candidate_id,action,actor,reason,idempotency_key,request_hash,expected_version,version,repair_plan_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,''),$12)`, decision.TenantID.String(), decision.ID.String(),
			decision.CandidateID.String(), string(decision.Action), decision.Actor, decision.Reason, decision.IdempotencyKey,
			decision.RequestHash, decision.ExpectedVersion, decision.Version, decision.RepairPlanID.String(), decision.CreatedAt); err != nil {
			return mapPostgresError(err, "create assessment relationship decision")
		}
		record, err = loadAssessmentRelationshipRecord(ctx, tx, decision.TenantID, decision.CandidateID, false)
		return err
	})
	return record, replayed, err
}

func loadAssessmentRelationshipRecord(ctx context.Context, tx pgx.Tx, tenantID, candidateID shared.ID, lock bool) (assessmentrelationship.Record, error) {
	query := `SELECT ` + assessmentRelationshipCandidateColumns + ` FROM assessment_relationship_candidates WHERE tenant_id=$1 AND id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	row := tx.QueryRow(ctx, query, tenantID.String(), candidateID.String())
	candidate, err := scanAssessmentRelationshipCandidate(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return assessmentrelationship.Record{}, shared.ErrNotFound
		}
		return assessmentrelationship.Record{}, err
	}
	record := assessmentrelationship.Record{Candidate: candidate}
	var decision assessmentrelationship.Decision
	var action, repairPlanID string
	err = tx.QueryRow(ctx, `SELECT tenant_id,id,candidate_id,action,actor,reason,idempotency_key,request_hash,
		expected_version,version,COALESCE(repair_plan_id,''),created_at FROM assessment_relationship_decisions
		WHERE tenant_id=$1 AND candidate_id=$2`, tenantID.String(), candidateID.String()).Scan(
		&decision.TenantID, &decision.ID, &decision.CandidateID, &action, &decision.Actor, &decision.Reason,
		&decision.IdempotencyKey, &decision.RequestHash, &decision.ExpectedVersion, &decision.Version, &repairPlanID, &decision.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return record, nil
	}
	if err != nil {
		return assessmentrelationship.Record{}, err
	}
	decision.Action, decision.RepairPlanID = assessmentrelationship.DecisionAction(action), shared.ID(repairPlanID)
	if err := decision.Validate(); err != nil {
		return assessmentrelationship.Record{}, fmt.Errorf("validate persisted relationship decision: %w", err)
	}
	record.Decision = &decision
	if decision.RepairPlanID.IsZero() {
		return record, nil
	}
	var plan assessmentrelationship.RepairPlan
	if err := tx.QueryRow(ctx, `SELECT tenant_id,id,candidate_id,input_hash,plan_hash,body,created_by,created_at
		FROM assessment_relationship_repair_plans WHERE tenant_id=$1 AND candidate_id=$2 AND id=$3`,
		tenantID.String(), candidateID.String(), decision.RepairPlanID.String()).Scan(&plan.TenantID, &plan.ID, &plan.CandidateID,
		&plan.InputHash, &plan.PlanHash, &plan.Body, &plan.CreatedBy, &plan.CreatedAt); err != nil {
		return assessmentrelationship.Record{}, err
	}
	if err := plan.Validate(); err != nil {
		return assessmentrelationship.Record{}, fmt.Errorf("validate persisted relationship repair plan: %w", err)
	}
	record.Plan = &plan
	return record, nil
}

type assessmentRelationshipScanner interface{ Scan(...any) error }

func scanAssessmentRelationshipCandidate(row assessmentRelationshipScanner) (assessmentrelationship.Candidate, error) {
	var candidate assessmentrelationship.Candidate
	var signals []byte
	if err := row.Scan(&candidate.TenantID, &candidate.ID, &candidate.PredecessorCycleID, &candidate.PredecessorAssessmentID,
		&candidate.PredecessorRelationshipVersion, &candidate.PredecessorSnapshotID, &candidate.PredecessorSnapshotHash,
		&candidate.SuccessorCycleID, &candidate.SuccessorAssessmentID, &candidate.SuccessorRelationshipVersion,
		&candidate.SuccessorSnapshotID, &candidate.SuccessorSnapshotHash, &candidate.BoundaryKeyHash, &signals,
		&candidate.InputHash, &candidate.Confidence, &candidate.ExpiresAt, &candidate.CreatedBy, &candidate.CreatedAt); err != nil {
		return assessmentrelationship.Candidate{}, err
	}
	if err := json.Unmarshal(signals, &candidate.Signals); err != nil {
		return assessmentrelationship.Candidate{}, fmt.Errorf("decode relationship candidate signals: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return assessmentrelationship.Candidate{}, fmt.Errorf("validate persisted relationship candidate: %w", err)
	}
	return candidate, nil
}
