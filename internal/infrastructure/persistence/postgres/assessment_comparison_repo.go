package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentComparisonRepository struct{ pool *pgxpool.Pool }

func NewAssessmentComparisonRepository(pool *pgxpool.Pool) *AssessmentComparisonRepository {
	return &AssessmentComparisonRepository{pool: pool}
}

var _ ports.AssessmentComparisonRepository = (*AssessmentComparisonRepository)(nil)

const assessmentComparisonColumns = `tenant_id,cycle_id,id,baseline_snapshot_id,current_snapshot_id,mode,input_hash,input_payload,
 algorithm_version,fingerprint_version,risk_model_version,coverage_policy_version,status,version,attempts,failure_code,content_hash,summary,
 created_at,updated_at,completed_at,superseded_at,superseded_by`

func (repository *AssessmentComparisonRepository) CreateQueued(ctx context.Context, comparison assessmentcomparison.Comparison) (assessmentcomparison.Comparison, bool, error) {
	comparison.TenantID = shared.TenantOrDefault(comparison.TenantID)
	if err := comparison.Validate(); err != nil {
		return assessmentcomparison.Comparison{}, false, err
	}
	var stored assessmentcomparison.Comparison
	created := false
	err := WithTenant(ctx, repository.pool, comparison.TenantID.String(), func(tx pgx.Tx) error {
		summary, err := marshalAssessmentComparisonSummary(comparison)
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `INSERT INTO assessment_comparisons (
 tenant_id,cycle_id,id,baseline_snapshot_id,current_snapshot_id,mode,input_hash,input_payload,
 algorithm_version,fingerprint_version,risk_model_version,coverage_policy_version,status,version,attempts,failure_code,content_hash,summary,
 created_at,updated_at,completed_at,superseded_at,superseded_by)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
 ON CONFLICT (tenant_id,input_hash) DO NOTHING`,
			comparison.TenantID.String(), comparison.CycleID.String(), comparison.ID.String(), comparison.BaselineSnapshotID.String(), comparison.CurrentSnapshotID.String(), string(comparison.Mode), comparison.InputHash, comparison.InputPayload,
			comparison.AlgorithmVersion, comparison.FingerprintVersion, comparison.RiskModelVersion, comparison.CoveragePolicyVersion, string(comparison.Status), comparison.Version, comparison.Attempts, comparison.FailureCode, comparison.ContentHash, summary,
			comparison.CreatedAt, comparison.UpdatedAt, comparison.CompletedAt, comparison.SupersededAt, nullableComparisonID(comparison.SupersededBy))
		if err != nil {
			return mapPostgresError(err, "create assessment comparison")
		}
		if result.RowsAffected() == 1 {
			stored, created = comparison, true
			return nil
		}
		existing, err := loadAssessmentComparisonByInputHash(ctx, tx, comparison.TenantID, comparison.InputHash, false)
		if err != nil {
			return err
		}
		if !samePostgresComparisonRequest(existing, comparison) {
			return fmt.Errorf("%w: comparison input hash was reused with different content", shared.ErrConflict)
		}
		stored = existing
		return nil
	})
	return stored, created, err
}

func (repository *AssessmentComparisonRepository) Get(ctx context.Context, tenantID, comparisonID shared.ID) (assessmentcomparison.Comparison, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var comparison assessmentcomparison.Comparison
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		comparison, err = loadAssessmentComparison(ctx, tx, tenantID, comparisonID, false)
		return err
	})
	return comparison, err
}

func (repository *AssessmentComparisonRepository) GetMetadata(ctx context.Context, tenantID, comparisonID shared.ID) (assessmentcomparison.Comparison, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var comparison assessmentcomparison.Comparison
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		comparison, err = loadAssessmentComparisonMetadata(ctx, tx, tenantID, comparisonID, false)
		return err
	})
	return comparison, err
}

func (repository *AssessmentComparisonRepository) GetByInputHash(ctx context.Context, tenantID shared.ID, inputHash string) (assessmentcomparison.Comparison, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var comparison assessmentcomparison.Comparison
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		comparison, err = loadAssessmentComparisonByInputHash(ctx, tx, tenantID, inputHash, false)
		return err
	})
	return comparison, err
}

func (repository *AssessmentComparisonRepository) ListMetadataByCycle(ctx context.Context, tenantID, cycleID shared.ID) ([]assessmentcomparison.Comparison, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var result []assessmentcomparison.Comparison
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+assessmentComparisonColumns+` FROM assessment_comparisons WHERE tenant_id=$1 AND cycle_id=$2 ORDER BY created_at,id`, tenantID.String(), cycleID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			comparison, err := scanAssessmentComparison(rows)
			if err != nil {
				return err
			}
			result = append(result, comparison)
		}
		return rows.Err()
	})
	return result, err
}

func (repository *AssessmentComparisonRepository) GetAssessmentComparisonBacklog(ctx context.Context, tenantID shared.ID) (ports.AssessmentComparisonBacklog, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var backlog ports.AssessmentComparisonBacklog
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var oldest pgtype.Timestamptz
		if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE status='queued'),
			count(*) FILTER (WHERE status='generating'),
			count(*) FILTER (WHERE status='failed'),
			count(*) FILTER (WHERE status='failed' AND failure_code='dead_lettered'),
			min(CASE WHEN status='queued' THEN created_at WHEN status='generating' THEN updated_at END)
			FROM assessment_comparisons WHERE tenant_id=$1`, tenantID.String()).Scan(
			&backlog.Queued, &backlog.Generating, &backlog.Failed, &backlog.DeadLettered, &oldest,
		); err != nil {
			return fmt.Errorf("read assessment comparison backlog: %w", err)
		}
		if oldest.Valid {
			value := oldest.Time.UTC()
			backlog.OldestActiveAt = &value
		}
		return nil
	})
	return backlog, err
}

func (repository *AssessmentComparisonRepository) ListFailedAssessmentComparisons(ctx context.Context, tenantID shared.ID, limit int) ([]assessmentcomparison.Comparison, error) {
	if limit < 1 || limit > 2000 {
		return nil, fmt.Errorf("%w: failed comparison limit must be between 1 and 2000", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	result := make([]assessmentcomparison.Comparison, 0)
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+assessmentComparisonColumns+` FROM assessment_comparisons
			WHERE tenant_id=$1 AND status='failed' ORDER BY updated_at,id LIMIT $2`, tenantID.String(), limit)
		if err != nil {
			return fmt.Errorf("list failed assessment comparisons: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			comparison, err := scanAssessmentComparison(rows)
			if err != nil {
				return err
			}
			result = append(result, comparison)
		}
		return rows.Err()
	})
	return result, err
}

func (repository *AssessmentComparisonRepository) GetItem(ctx context.Context, tenantID, comparisonID, itemID shared.ID) (assessmentcomparison.Item, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var item assessmentcomparison.Item
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		item, err = scanAssessmentComparisonItem(tx.QueryRow(ctx, `SELECT id,position,identity_id,producer_kind,finding_kind,target_canonical,baseline_observation_id,current_observation_id,baseline_observation,current_observation,presence,neutral_presence,change_flags,coverage_decision,match_methods,verification_id,verification_state,fixed_basis,
 baseline_actionable,current_actionable,comparable_baseline,baseline_risk_milli,current_risk_milli,review_candidate_ids,review_candidates
 FROM assessment_comparison_items WHERE tenant_id=$1 AND comparison_id=$2 AND id=$3`, tenantID.String(), comparisonID.String(), itemID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return err
	})
	return item, err
}

func (repository *AssessmentComparisonRepository) ListItems(ctx context.Context, tenantID, comparisonID shared.ID, filter ports.AssessmentComparisonItemFilter) (ports.AssessmentComparisonItemPage, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	var page ports.AssessmentComparisonItemPage
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := loadAssessmentComparisonMetadata(ctx, tx, tenantID, comparisonID, false); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id,position,identity_id,producer_kind,finding_kind,target_canonical,baseline_observation_id,current_observation_id,baseline_observation,current_observation,presence,neutral_presence,change_flags,coverage_decision,match_methods,verification_id,verification_state,fixed_basis,
 baseline_actionable,current_actionable,comparable_baseline,baseline_risk_milli,current_risk_milli,review_candidate_ids,review_candidates
 FROM assessment_comparison_items
 WHERE tenant_id=$1 AND comparison_id=$2 AND position>$3
	   AND ($4='' OR presence=$4 OR neutral_presence=$4)
	   AND ($5='' OR change_flags ? $5)
	   AND ($6='' OR COALESCE(NULLIF(current_observation->>'severity',''),baseline_observation->>'severity')=$6)
	   AND ($7='' OR producer_kind=$7)
	   AND ($8='' OR finding_kind=$8)
	   AND ($9='' OR CASE WHEN current_actionable THEN 'current_actionable' WHEN baseline_actionable THEN 'baseline_only' ELSE 'non_actionable' END=$9)
	   AND ($10='' OR CASE WHEN presence='needs_review' OR neutral_presence='needs_review' OR jsonb_array_length(review_candidate_ids)>0 THEN 'needs_review' WHEN verification_id IS NOT NULL THEN 'verified' ELSE 'clear' END=$10)
	 ORDER BY position LIMIT $11`, tenantID.String(), comparisonID.String(), filter.AfterPosition, filter.Presence, string(filter.ChangeFlag), string(filter.Severity), filter.ProducerKind, filter.FindingKind, filter.Disposition, filter.ReviewState, filter.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanAssessmentComparisonItem(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Items) > filter.Limit {
			page.Items, page.HasMore = page.Items[:filter.Limit], true
		}
		if len(page.Items) > 0 {
			page.NextPosition = page.Items[len(page.Items)-1].Position
		} else {
			page.NextPosition = filter.AfterPosition
		}
		return nil
	})
	return page, err
}

func (repository *AssessmentComparisonRepository) UpdateCAS(ctx context.Context, comparison assessmentcomparison.Comparison, expectedVersion int64) error {
	comparison.TenantID = shared.TenantOrDefault(comparison.TenantID)
	if err := comparison.Validate(); err != nil {
		return err
	}
	return WithTenant(ctx, repository.pool, comparison.TenantID.String(), func(tx pgx.Tx) error {
		existing, err := loadAssessmentComparison(ctx, tx, comparison.TenantID, comparison.ID, true)
		if err != nil {
			return err
		}
		if existing.Version != expectedVersion || comparison.Version != expectedVersion+1 || !samePostgresComparisonImmutable(existing, comparison) || !postgresComparisonTransition(existing.Status, comparison.Status) {
			return fmt.Errorf("%w: comparison version or transition mismatch", shared.ErrConflict)
		}
		if comparison.Status == assessmentcomparison.StatusComplete || comparison.Status == assessmentcomparison.StatusNeedsReview {
			for _, item := range comparison.Items {
				flags, err := json.Marshal(item.ChangeFlags)
				if err != nil {
					return err
				}
				candidateIDs, err := json.Marshal(item.ReviewCandidateIDs)
				if err != nil {
					return err
				}
				reviewCandidates, err := json.Marshal(item.ReviewCandidates)
				if err != nil {
					return err
				}
				baselineObservation, err := json.Marshal(item.BaselineObservation)
				if err != nil {
					return err
				}
				currentObservation, err := json.Marshal(item.CurrentObservation)
				if err != nil {
					return err
				}
				matchMethods, err := json.Marshal(item.MatchMethods)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO assessment_comparison_items (
	 tenant_id,cycle_id,comparison_id,id,position,identity_id,producer_kind,finding_kind,target_canonical,baseline_observation_id,current_observation_id,baseline_observation,current_observation,presence,neutral_presence,change_flags,coverage_decision,match_methods,
	 verification_id,verification_state,fixed_basis,baseline_actionable,current_actionable,comparable_baseline,baseline_risk_milli,current_risk_milli,review_candidate_ids,review_candidates)
	 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`,
					comparison.TenantID.String(), comparison.CycleID.String(), comparison.ID.String(), item.ID.String(), item.Position, item.IdentityID.String(), item.ProducerKind, item.FindingKind, item.TargetCanonical, nullableComparisonID(item.BaselineObservationID), nullableComparisonID(item.CurrentObservationID), baselineObservation, currentObservation, string(item.Presence), string(item.NeutralPresence), flags, string(item.CoverageDecision), matchMethods,
					nullableComparisonID(item.VerificationID), item.VerificationState, string(item.FixedBasis), item.BaselineActionable, item.CurrentActionable, item.ComparableBaseline, item.BaselineRiskMilli, item.CurrentRiskMilli, candidateIDs, reviewCandidates); err != nil {
					return err
				}
			}
		}
		summary, err := marshalAssessmentComparisonSummary(comparison)
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `UPDATE assessment_comparisons SET status=$1,version=$2,attempts=$3,failure_code=$4,content_hash=$5,summary=$6,
 updated_at=$7,completed_at=$8,superseded_at=$9,superseded_by=$10 WHERE tenant_id=$11 AND cycle_id=$12 AND id=$13 AND version=$14`,
			string(comparison.Status), comparison.Version, comparison.Attempts, comparison.FailureCode, comparison.ContentHash, summary,
			comparison.UpdatedAt, comparison.CompletedAt, comparison.SupersededAt, nullableComparisonID(comparison.SupersededBy),
			comparison.TenantID.String(), comparison.CycleID.String(), comparison.ID.String(), expectedVersion)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return fmt.Errorf("%w: comparison version mismatch", shared.ErrConflict)
		}
		return nil
	})
}

func loadAssessmentComparison(ctx context.Context, tx pgx.Tx, tenantID, comparisonID shared.ID, lock bool) (assessmentcomparison.Comparison, error) {
	comparison, err := loadAssessmentComparisonMetadata(ctx, tx, tenantID, comparisonID, lock)
	if err != nil {
		return assessmentcomparison.Comparison{}, err
	}
	return loadAssessmentComparisonItems(ctx, tx, comparison)
}

func loadAssessmentComparisonMetadata(ctx context.Context, tx pgx.Tx, tenantID, comparisonID shared.ID, lock bool) (assessmentcomparison.Comparison, error) {
	query := `SELECT ` + assessmentComparisonColumns + ` FROM assessment_comparisons WHERE tenant_id=$1 AND id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	return scanAssessmentComparison(tx.QueryRow(ctx, query, tenantID.String(), comparisonID.String()))
}

func loadAssessmentComparisonByInputHash(ctx context.Context, tx pgx.Tx, tenantID shared.ID, inputHash string, lock bool) (assessmentcomparison.Comparison, error) {
	query := `SELECT ` + assessmentComparisonColumns + ` FROM assessment_comparisons WHERE tenant_id=$1 AND input_hash=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	comparison, err := scanAssessmentComparison(tx.QueryRow(ctx, query, tenantID.String(), inputHash))
	if err != nil {
		return assessmentcomparison.Comparison{}, err
	}
	return loadAssessmentComparisonItems(ctx, tx, comparison)
}

func scanAssessmentComparison(row rowScanner) (assessmentcomparison.Comparison, error) {
	var comparison assessmentcomparison.Comparison
	var mode, status string
	var summary []byte
	var supersededBy *string
	if err := row.Scan(&comparison.TenantID, &comparison.CycleID, &comparison.ID, &comparison.BaselineSnapshotID, &comparison.CurrentSnapshotID, &mode, &comparison.InputHash, &comparison.InputPayload,
		&comparison.AlgorithmVersion, &comparison.FingerprintVersion, &comparison.RiskModelVersion, &comparison.CoveragePolicyVersion, &status, &comparison.Version, &comparison.Attempts, &comparison.FailureCode, &comparison.ContentHash, &summary,
		&comparison.CreatedAt, &comparison.UpdatedAt, &comparison.CompletedAt, &comparison.SupersededAt, &supersededBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return assessmentcomparison.Comparison{}, shared.ErrNotFound
		}
		return assessmentcomparison.Comparison{}, err
	}
	comparison.Mode, comparison.Status = assessmentcomparison.Mode(mode), assessmentcomparison.Status(status)
	if supersededBy != nil {
		comparison.SupersededBy = shared.ID(*supersededBy)
	}
	if err := json.Unmarshal(summary, &comparison.Summary); err != nil {
		return assessmentcomparison.Comparison{}, err
	}
	return comparison, nil
}

func loadAssessmentComparisonItems(ctx context.Context, tx pgx.Tx, comparison assessmentcomparison.Comparison) (assessmentcomparison.Comparison, error) {
	rows, err := tx.Query(ctx, `SELECT id,position,identity_id,producer_kind,finding_kind,target_canonical,baseline_observation_id,current_observation_id,baseline_observation,current_observation,presence,neutral_presence,change_flags,coverage_decision,match_methods,verification_id,verification_state,fixed_basis,
 baseline_actionable,current_actionable,comparable_baseline,baseline_risk_milli,current_risk_milli,review_candidate_ids,review_candidates
 FROM assessment_comparison_items WHERE tenant_id=$1 AND cycle_id=$2 AND comparison_id=$3 ORDER BY position`, comparison.TenantID.String(), comparison.CycleID.String(), comparison.ID.String())
	if err != nil {
		return assessmentcomparison.Comparison{}, err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanAssessmentComparisonItem(rows)
		if err != nil {
			return assessmentcomparison.Comparison{}, err
		}
		comparison.Items = append(comparison.Items, item)
	}
	return comparison, rows.Err()
}

func scanAssessmentComparisonItem(row rowScanner) (assessmentcomparison.Item, error) {
	var item assessmentcomparison.Item
	var baselineID, currentID, verificationID *string
	var presence, neutral, coverage string
	var flags, candidateIDs, reviewCandidates, baselineObservation, currentObservation, matchMethods []byte
	if err := row.Scan(&item.ID, &item.Position, &item.IdentityID, &item.ProducerKind, &item.FindingKind, &item.TargetCanonical, &baselineID, &currentID, &baselineObservation, &currentObservation, &presence, &neutral, &flags, &coverage, &matchMethods, &verificationID, &item.VerificationState, &item.FixedBasis,
		&item.BaselineActionable, &item.CurrentActionable, &item.ComparableBaseline, &item.BaselineRiskMilli, &item.CurrentRiskMilli, &candidateIDs, &reviewCandidates); err != nil {
		return assessmentcomparison.Item{}, err
	}
	item.Presence, item.NeutralPresence, item.CoverageDecision = assessmentcomparison.Presence(presence), assessmentcomparison.NeutralPresence(neutral), assessmentsnapshot.Comparability(coverage)
	if baselineID != nil {
		item.BaselineObservationID = shared.ID(*baselineID)
	}
	if currentID != nil {
		item.CurrentObservationID = shared.ID(*currentID)
	}
	if verificationID != nil {
		item.VerificationID = shared.ID(*verificationID)
	}
	if err := json.Unmarshal(flags, &item.ChangeFlags); err != nil {
		return assessmentcomparison.Item{}, err
	}
	if err := json.Unmarshal(baselineObservation, &item.BaselineObservation); err != nil {
		return assessmentcomparison.Item{}, err
	}
	if err := json.Unmarshal(currentObservation, &item.CurrentObservation); err != nil {
		return assessmentcomparison.Item{}, err
	}
	if err := json.Unmarshal(matchMethods, &item.MatchMethods); err != nil {
		return assessmentcomparison.Item{}, err
	}
	if err := json.Unmarshal(candidateIDs, &item.ReviewCandidateIDs); err != nil {
		return assessmentcomparison.Item{}, err
	}
	if err := json.Unmarshal(reviewCandidates, &item.ReviewCandidates); err != nil {
		return assessmentcomparison.Item{}, err
	}
	return item, nil
}

func samePostgresComparisonRequest(left, right assessmentcomparison.Comparison) bool {
	return left.TenantID == right.TenantID && left.CycleID == right.CycleID && left.BaselineSnapshotID == right.BaselineSnapshotID && left.CurrentSnapshotID == right.CurrentSnapshotID &&
		left.Mode == right.Mode && left.InputHash == right.InputHash && jsonPayloadEqual(left.InputPayload, right.InputPayload) && left.AlgorithmVersion == right.AlgorithmVersion &&
		left.FingerprintVersion == right.FingerprintVersion && left.RiskModelVersion == right.RiskModelVersion && left.CoveragePolicyVersion == right.CoveragePolicyVersion
}

func samePostgresComparisonImmutable(left, right assessmentcomparison.Comparison) bool {
	return samePostgresComparisonRequest(left, right) && left.ID == right.ID && left.CreatedAt.Equal(right.CreatedAt)
}

func postgresComparisonTransition(from, to assessmentcomparison.Status) bool {
	switch from {
	case assessmentcomparison.StatusQueued:
		return to == assessmentcomparison.StatusGenerating
	case assessmentcomparison.StatusGenerating:
		return to == assessmentcomparison.StatusQueued || to == assessmentcomparison.StatusComplete || to == assessmentcomparison.StatusNeedsReview || to == assessmentcomparison.StatusFailed
	case assessmentcomparison.StatusFailed:
		return to == assessmentcomparison.StatusGenerating
	case assessmentcomparison.StatusComplete, assessmentcomparison.StatusNeedsReview:
		return to == assessmentcomparison.StatusSuperseded
	}
	return false
}

func jsonPayloadEqual(left, right []byte) bool {
	var a, b any
	return json.Unmarshal(left, &a) == nil && json.Unmarshal(right, &b) == nil && reflect.DeepEqual(a, b)
}

func nullableComparisonID(id shared.ID) any {
	if id.IsZero() {
		return nil
	}
	return id.String()
}

func marshalAssessmentComparisonSummary(comparison assessmentcomparison.Comparison) ([]byte, error) {
	if comparison.Status == assessmentcomparison.StatusQueued || comparison.Status == assessmentcomparison.StatusGenerating || comparison.Status == assessmentcomparison.StatusFailed {
		return []byte("{}"), nil
	}
	return json.Marshal(comparison.Summary)
}
