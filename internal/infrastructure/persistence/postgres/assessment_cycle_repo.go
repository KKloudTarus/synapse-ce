package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const assessmentCycleCols = `tenant_id, id, name, boundary_kind, business_asset_id, project_id, status, root_assessment_id, selected_head_assessment_id, next_retest_number, version, created_at, updated_at, created_by, updated_by, active_closure_manifest_id, active_closure_cycle_version`
const assessmentCycleMemberCols = `tenant_id, cycle_id, assessment_id, assessment_type, predecessor_assessment_id, retest_number, relationship_version, created_at, created_by, archived_at`

// AssessmentCycleRepository persists AssessmentCycle aggregates and their members to PostgreSQL.
type AssessmentCycleRepository struct {
	pool *pgxpool.Pool
}

// NewAssessmentCycleRepository returns a repository backed by the given pool.
func NewAssessmentCycleRepository(pool *pgxpool.Pool) *AssessmentCycleRepository {
	return &AssessmentCycleRepository{pool: pool}
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

	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		query := `INSERT INTO assessment_cycles (` + assessmentCycleCols + `)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $10, $11, $12, $13, $14, $15, NULLIF($16, ''), NULLIF($17, 0))`

		_, err := tx.Exec(ctx, query,
			tenantID.String(),
			cycle.ID.String(),
			cycle.Name,
			string(cycle.BoundaryKind),
			cycle.BusinessAssetID.String(),
			cycle.ProjectID.String(),
			string(cycle.Status),
			cycle.RootAssessmentID.String(),
			cycle.SelectedHeadAssessmentID.String(),
			cycle.NextRetestNumber,
			cycle.Version,
			cycle.CreatedAt,
			cycle.UpdatedAt,
			cycle.CreatedBy,
			cycle.UpdatedBy,
			cycle.ActiveClosureManifestID.String(),
			cycle.ActiveClosureCycleVersion,
		)
		if err != nil {
			return mapPostgresError(err, "create assessment cycle")
		}
		return nil
	})
}

func (r *AssessmentCycleRepository) GetCycle(ctx context.Context, tenantID, cycleID shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}

	var cycle *assessmentcycle.AssessmentCycle
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		query := `SELECT ` + assessmentCycleCols + ` FROM assessment_cycles WHERE tenant_id = $1 AND id = $2`
		row := tx.QueryRow(ctx, query, tenantID.String(), cycleID.String())
		c, err := scanAssessmentCycle(row)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, cycleID)
			}
			return err
		}
		cycle = c
		return nil
	})
	return cycle, err
}

func (r *AssessmentCycleRepository) GetCycleByAssessment(ctx context.Context, tenantID, assessmentID shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || assessmentID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and assessment ids are required", shared.ErrValidation)
	}

	var cycle *assessmentcycle.AssessmentCycle
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		query := `SELECT c.tenant_id, c.id, c.name, c.boundary_kind, c.business_asset_id, c.project_id, c.status,
				c.root_assessment_id, c.selected_head_assessment_id, c.next_retest_number, c.version,
				c.created_at, c.updated_at, c.created_by, c.updated_by, c.active_closure_manifest_id, c.active_closure_cycle_version
			FROM assessment_cycles c
			JOIN assessment_cycle_members m ON c.tenant_id = m.tenant_id AND c.id = m.cycle_id
			WHERE m.tenant_id = $1 AND m.assessment_id = $2`

		row := tx.QueryRow(ctx, query, tenantID.String(), assessmentID.String())
		c, err := scanAssessmentCycle(row)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: assessment %q does not belong to any cycle", shared.ErrNotFound, assessmentID)
			}
			return err
		}
		cycle = c
		return nil
	})
	return cycle, err
}

func (r *AssessmentCycleRepository) ListCycles(ctx context.Context, query ports.AssessmentCycleListQuery) ([]ports.AssessmentCycleListRecord, error) {
	tenantID := shared.TenantOrDefault(query.TenantID)
	if tenantID.IsZero() || query.Limit <= 0 {
		return nil, fmt.Errorf("%w: tenant and positive cycle list limit are required", shared.ErrValidation)
	}
	if query.MemberLimit <= 0 {
		query.MemberLimit = 10
	}
	records := make([]ports.AssessmentCycleListRecord, 0, query.Limit)
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT c.tenant_id, c.id, c.name, c.boundary_kind, c.business_asset_id, c.project_id, c.status,
			       c.root_assessment_id, c.selected_head_assessment_id, c.next_retest_number, c.version,
			       c.created_at, c.updated_at, c.created_by, c.updated_by,
			       COALESCE(stats.member_count, 0), COALESCE(stats.branch_count, 0),
			       COALESCE(latest.assessment_id, ''), COALESCE(latest.retest_number, -1),
			       COALESCE(member_page.members, '[]'::jsonb),
			       COALESCE(CASE WHEN c.status = 'completed' THEN active_manifest.initial_snapshot_id ELSE root_default.snapshot_id END, ''),
			       COALESCE(CASE WHEN c.status = 'completed' THEN active_manifest.final_snapshot_id ELSE current_default.snapshot_id END, ''),
			       COALESCE(comparison.id, ''), COALESCE(comparison.status, ''), COALESCE(comparison.summary, '{}'::jsonb),
			       COALESCE(c.active_closure_manifest_id, ''), latest_scan.last_scan_at,
			       CASE WHEN latest_scan.last_scan_at IS NULL THEN 'missing'
			            WHEN latest_scan.last_scan_at >= $17::timestamptz THEN 'fresh' ELSE 'stale' END
			FROM assessment_cycles c
			JOIN engagements selected_head
			  ON selected_head.tenant_id = c.tenant_id AND selected_head.id = c.selected_head_assessment_id
			LEFT JOIN LATERAL (
				SELECT COUNT(*)::int AS member_count,
				       COUNT(*) FILTER (WHERE member.archived_at IS NULL AND NOT EXISTS (
					       SELECT 1 FROM assessment_cycle_members child
					       WHERE child.tenant_id = member.tenant_id AND child.cycle_id = member.cycle_id
					         AND child.predecessor_assessment_id = member.assessment_id AND child.archived_at IS NULL
				       ))::int AS branch_count
				FROM assessment_cycle_members member
				WHERE member.tenant_id = c.tenant_id AND member.cycle_id = c.id
			) stats ON true
			LEFT JOIN LATERAL (
				SELECT member.assessment_id, member.retest_number
				FROM assessment_cycle_members member
				WHERE member.tenant_id = c.tenant_id AND member.cycle_id = c.id AND member.archived_at IS NULL
				ORDER BY member.retest_number DESC, member.assessment_id DESC
				LIMIT 1
			) latest ON true
			LEFT JOIN LATERAL (
				SELECT jsonb_agg(jsonb_build_object(
					'assessment_id', member.assessment_id,
					'assessment_type', member.assessment_type,
					'predecessor_assessment_id', COALESCE(member.predecessor_assessment_id, ''),
					'retest_number', member.retest_number,
					'relationship_version', member.relationship_version,
					'created_at', member.created_at,
					'created_by', member.created_by,
					'archived_at', member.archived_at
				) ORDER BY member.retest_number, member.assessment_id) AS members
				FROM (
					SELECT member.* FROM assessment_cycle_members member
					WHERE member.tenant_id = c.tenant_id AND member.cycle_id = c.id
					ORDER BY member.retest_number, member.assessment_id
					LIMIT $7
				) member
			) member_page ON true
			LEFT JOIN assessment_snapshot_defaults root_default
			  ON root_default.tenant_id = c.tenant_id AND root_default.assessment_id = c.root_assessment_id
			LEFT JOIN assessment_snapshot_defaults current_default
			  ON current_default.tenant_id = c.tenant_id AND current_default.assessment_id = c.selected_head_assessment_id
			LEFT JOIN assessment_cycle_closure_manifests active_manifest
			  ON active_manifest.tenant_id = c.tenant_id AND active_manifest.cycle_id = c.id
			 AND active_manifest.id = c.active_closure_manifest_id AND active_manifest.lifecycle = 'active'
			LEFT JOIN LATERAL (
				SELECT value.id, value.status, value.summary
				FROM assessment_comparisons value
				WHERE value.tenant_id = c.tenant_id AND value.cycle_id = c.id
				  AND value.mode = 'lifecycle'
				  AND ((c.status = 'completed' AND active_manifest.id IS NOT NULL
				        AND value.id = active_manifest.comparison_id
				        AND value.baseline_snapshot_id = active_manifest.initial_snapshot_id
				        AND value.current_snapshot_id = active_manifest.final_snapshot_id
				        AND value.status IN ('complete','superseded'))
				    OR (c.status <> 'completed'
				        AND value.baseline_snapshot_id = root_default.snapshot_id
				        AND value.current_snapshot_id = current_default.snapshot_id
				        AND value.status IN ('complete','needs_review')))
				ORDER BY value.completed_at DESC, value.id DESC
					LIMIT 1
				) comparison ON true
			LEFT JOIN LATERAL (
				SELECT MAX(run.sealed_at) AS last_scan_at
				FROM scan_runs run
				WHERE run.tenant_id = c.tenant_id AND run.engagement_id = c.selected_head_assessment_id
				  AND run.provenance = 'native' AND run.terminal_status IN ('succeeded','partial') AND run.sealed_at IS NOT NULL
			) latest_scan ON true
			WHERE c.tenant_id = $1
			  AND ($2 = '' OR c.status = $2)
			  AND ($3 = '' OR c.boundary_kind = $3)
			  AND ($4::timestamptz IS NULL OR c.updated_at < $4 OR (c.updated_at = $4 AND c.id < $5))
			  AND ($8 = '' OR selected_head.status = $8)
			  AND ($9 = '' OR c.selected_head_assessment_id = $9)
			  AND ($10 = '' OR EXISTS (
				  SELECT 1 FROM assessment_cycle_members filtered_member
				  WHERE filtered_member.tenant_id = c.tenant_id AND filtered_member.cycle_id = c.id AND filtered_member.assessment_type = $10
			  ))
			  AND (($11 = '' AND $12 = '' AND $13 = '' AND $14 = '' AND $15 = '') OR EXISTS (
				  SELECT 1 FROM assessment_comparison_items filtered_item
				  WHERE filtered_item.tenant_id = c.tenant_id AND filtered_item.cycle_id = c.id AND filtered_item.comparison_id = comparison.id
				    AND ($11 = '' OR filtered_item.producer_kind = $11)
				    AND ($12 = '' OR filtered_item.finding_kind = $12)
				    AND ($13 = '' OR CASE
				      WHEN filtered_item.presence = 'needs_review' OR filtered_item.neutral_presence = 'needs_review' OR jsonb_array_length(filtered_item.review_candidate_ids) > 0 THEN 'needs_review'
				      WHEN filtered_item.verification_id IS NOT NULL THEN 'verified' ELSE 'clear' END = $13)
				    AND ($14 = '' OR filtered_item.presence = $14)
				    AND ($15 = '' OR COALESCE(NULLIF(filtered_item.current_observation->>'severity',''), filtered_item.baseline_observation->>'severity') = $15)
			  ))
			  AND ($16 = '' OR CASE WHEN latest_scan.last_scan_at IS NULL THEN 'missing'
			      WHEN latest_scan.last_scan_at >= $17::timestamptz THEN 'fresh' ELSE 'stale' END = $16)
			  AND ($18 = '' OR position(lower($18) in lower(c.name)) > 0 OR position(lower($18) in lower(c.id)) > 0
			      OR position(lower($18) in lower(c.root_assessment_id)) > 0 OR position(lower($18) in lower(c.selected_head_assessment_id)) > 0)
			ORDER BY c.updated_at DESC, c.id DESC
			LIMIT $6`, tenantID.String(), string(query.Status), string(query.BoundaryKind), nullableCycleCursorTime(query.AfterUpdatedAt), query.AfterCycleID.String(), query.Limit, query.MemberLimit+1,
			string(query.AssessmentStatus), query.SelectedHeadID.String(), string(query.AssessmentType), query.ProducerKind, query.FindingKind, query.ReviewState,
			string(query.ChangePresence), string(query.ChangeSeverity), query.ScanStaleness, query.ScanStaleBefore, query.Search)
		if err != nil {
			return fmt.Errorf("list assessment cycles: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			cycle, record, err := scanAssessmentCycleListRecord(rows, query.MemberLimit)
			if err != nil {
				return err
			}
			record.Cycle = *cycle
			records = append(records, record)
		}
		return rows.Err()
	})
	return records, err
}

func (r *AssessmentCycleRepository) ListMigrationPendingAssessments(ctx context.Context, query ports.AssessmentCycleListQuery) ([]ports.AssessmentCycleMigrationPendingRecord, int, error) {
	tenantID := shared.TenantOrDefault(query.TenantID)
	if tenantID.IsZero() || query.Limit < 1 || query.Limit > 100 {
		return nil, 0, fmt.Errorf("%w: tenant and bounded migration-pending limit are required", shared.ErrValidation)
	}
	records := make([]ports.AssessmentCycleMigrationPendingRecord, 0, query.Limit)
	total := 0
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		predicate := `e.tenant_id=$1 AND e.project_id IS NULL AND NOT EXISTS (
			SELECT 1 FROM assessment_cycle_members member WHERE member.tenant_id=e.tenant_id AND member.assessment_id=e.id)`
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM engagements e WHERE `+predicate, tenantID.String()).Scan(&total); err != nil {
			return fmt.Errorf("count migration-pending assessments: %w", err)
		}
		if query.Status != "" || !query.SelectedHeadID.IsZero() || query.AssessmentType != "" || query.ProducerKind != "" || query.FindingKind != "" ||
			query.ReviewState != "" || query.ChangePresence != "" || query.ChangeSeverity != "" || query.ScanStaleness != "" {
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT e.id,e.name,e.status,
			CASE WHEN e.business_asset_id IS NULL THEN 'standalone' ELSE 'asset' END,
			COALESCE(e.business_asset_id,''),e.updated_at
			FROM engagements e WHERE `+predicate+`
			AND ($2 = '' OR e.status = $2)
			AND ($3 = '' OR CASE WHEN e.business_asset_id IS NULL THEN 'standalone' ELSE 'asset' END = $3)
			AND ($4 = '' OR position(lower($4) in lower(e.name)) > 0 OR position(lower($4) in lower(e.id)) > 0)
			ORDER BY e.updated_at DESC,e.id DESC LIMIT $5`, tenantID.String(), string(query.AssessmentStatus), string(query.BoundaryKind), query.Search, query.Limit)
		if err != nil {
			return fmt.Errorf("list migration-pending assessments: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var record ports.AssessmentCycleMigrationPendingRecord
			if err := rows.Scan(&record.AssessmentID, &record.Name, &record.Status, &record.BoundaryKind, &record.BusinessAssetID, &record.UpdatedAt); err != nil {
				return fmt.Errorf("scan migration-pending assessment: %w", err)
			}
			records = append(records, record)
		}
		return rows.Err()
	})
	return records, total, err
}

func (r *AssessmentCycleRepository) DeleteCycle(ctx context.Context, tenantID, cycleID shared.ID) error {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM assessment_cycles WHERE tenant_id=$1 AND id=$2`, tenantID.String(), cycleID.String())
		return err
	})
}

func (r *AssessmentCycleRepository) DeleteMember(ctx context.Context, tenantID, cycleID, assessmentID shared.ID) error {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() || assessmentID.IsZero() {
		return fmt.Errorf("%w: tenant, cycle, and assessment ids are required", shared.ErrValidation)
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM assessment_cycle_members WHERE tenant_id=$1 AND cycle_id=$2 AND assessment_id=$3`, tenantID.String(), cycleID.String(), assessmentID.String())
		return err
	})
}

func (r *AssessmentCycleRepository) UpdateCycleCAS(ctx context.Context, cycle *assessmentcycle.AssessmentCycle, expectedVersion int64) error {
	if cycle == nil {
		return fmt.Errorf("%w: cycle is nil", shared.ErrValidation)
	}
	if err := cycle.Validate(); err != nil {
		return err
	}

	tenantID := shared.TenantOrDefault(cycle.TenantID)

	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var query string
		var args []any

		if expectedVersion > 0 {
			query = `UPDATE assessment_cycles
				SET name = $3, boundary_kind = $4, business_asset_id = NULLIF($5, ''), project_id = NULLIF($6, ''),
				    status = $7, selected_head_assessment_id = $8, next_retest_number = $9, version = $10,
				    updated_at = $11, updated_by = $12, active_closure_manifest_id = NULLIF($13, ''), active_closure_cycle_version = NULLIF($14, 0)
				WHERE tenant_id = $1 AND id = $2 AND version = $15`
			args = []any{
				tenantID.String(),
				cycle.ID.String(),
				cycle.Name,
				string(cycle.BoundaryKind),
				cycle.BusinessAssetID.String(),
				cycle.ProjectID.String(),
				string(cycle.Status),
				cycle.SelectedHeadAssessmentID.String(),
				cycle.NextRetestNumber,
				cycle.Version,
				cycle.UpdatedAt,
				cycle.UpdatedBy,
				cycle.ActiveClosureManifestID.String(),
				cycle.ActiveClosureCycleVersion,
				expectedVersion,
			}
		} else {
			query = `UPDATE assessment_cycles
				SET name = $3, boundary_kind = $4, business_asset_id = NULLIF($5, ''), project_id = NULLIF($6, ''),
				    status = $7, selected_head_assessment_id = $8, next_retest_number = $9, version = $10,
				    updated_at = $11, updated_by = $12, active_closure_manifest_id = NULLIF($13, ''), active_closure_cycle_version = NULLIF($14, 0)
				WHERE tenant_id = $1 AND id = $2`
			args = []any{
				tenantID.String(),
				cycle.ID.String(),
				cycle.Name,
				string(cycle.BoundaryKind),
				cycle.BusinessAssetID.String(),
				cycle.ProjectID.String(),
				string(cycle.Status),
				cycle.SelectedHeadAssessmentID.String(),
				cycle.NextRetestNumber,
				cycle.Version,
				cycle.UpdatedAt,
				cycle.UpdatedBy,
				cycle.ActiveClosureManifestID.String(),
				cycle.ActiveClosureCycleVersion,
			}
		}

		tag, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return mapPostgresError(err, "update assessment cycle")
		}

		if tag.RowsAffected() == 0 {
			var exists bool
			_ = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assessment_cycles WHERE tenant_id = $1 AND id = $2)`, tenantID.String(), cycle.ID.String()).Scan(&exists)
			if !exists {
				return fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, cycle.ID)
			}
			return fmt.Errorf("%w: assessment cycle version mismatch (expected %d)", shared.ErrConflict, expectedVersion)
		}

		return nil
	})
}

func (r *AssessmentCycleRepository) CreateMember(ctx context.Context, member *assessmentcycle.Member) error {
	if member == nil {
		return fmt.Errorf("%w: member is nil", shared.ErrValidation)
	}
	if err := member.Validate(); err != nil {
		return err
	}

	tenantID := shared.TenantOrDefault(member.TenantID)

	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		query := `INSERT INTO assessment_cycle_members (` + assessmentCycleMemberCols + `)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9, $10)`

		_, err := tx.Exec(ctx, query,
			tenantID.String(),
			member.CycleID.String(),
			member.AssessmentID.String(),
			string(member.AssessmentType),
			member.PredecessorAssessmentID.String(),
			member.RetestNumber,
			member.RelationshipVersion,
			member.CreatedAt,
			member.CreatedBy,
			member.ArchivedAt,
		)
		if err != nil {
			return mapPostgresError(err, "create assessment cycle member")
		}
		return nil
	})
}

func (r *AssessmentCycleRepository) GetMember(ctx context.Context, tenantID, cycleID, assessmentID shared.ID) (*assessmentcycle.Member, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() || assessmentID.IsZero() {
		return nil, fmt.Errorf("%w: tenant, cycle, and assessment ids are required", shared.ErrValidation)
	}

	var member *assessmentcycle.Member
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		query := `SELECT ` + assessmentCycleMemberCols + ` FROM assessment_cycle_members WHERE tenant_id = $1 AND cycle_id = $2 AND assessment_id = $3`
		row := tx.QueryRow(ctx, query, tenantID.String(), cycleID.String(), assessmentID.String())
		m, err := scanAssessmentCycleMember(row)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: member %q not found in cycle %q", shared.ErrNotFound, assessmentID, cycleID)
			}
			return err
		}
		member = m
		return nil
	})
	return member, err
}

func (r *AssessmentCycleRepository) ListMembers(ctx context.Context, tenantID, cycleID shared.ID) ([]assessmentcycle.Member, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}

	var members []assessmentcycle.Member
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		query := `SELECT ` + assessmentCycleMemberCols + ` FROM assessment_cycle_members WHERE tenant_id = $1 AND cycle_id = $2 ORDER BY retest_number ASC, assessment_id ASC`
		rows, err := tx.Query(ctx, query, tenantID.String(), cycleID.String())
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			m, err := scanAssessmentCycleMember(rows)
			if err != nil {
				return err
			}
			members = append(members, *m)
		}
		return rows.Err()
	})
	return members, err
}

func (r *AssessmentCycleRepository) UpdateMemberCAS(ctx context.Context, member *assessmentcycle.Member, expectedVersion int64) error {
	if member == nil {
		return fmt.Errorf("%w: member is nil", shared.ErrValidation)
	}
	if err := member.Validate(); err != nil {
		return err
	}

	tenantID := shared.TenantOrDefault(member.TenantID)

	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var query string
		var args []any

		if expectedVersion > 0 {
			query = `UPDATE assessment_cycle_members
				SET predecessor_assessment_id = NULLIF($4, ''), relationship_version = $5, archived_at = $6
				WHERE tenant_id = $1 AND cycle_id = $2 AND assessment_id = $3 AND relationship_version = $7`
			args = []any{
				tenantID.String(),
				member.CycleID.String(),
				member.AssessmentID.String(),
				member.PredecessorAssessmentID.String(),
				member.RelationshipVersion,
				member.ArchivedAt,
				expectedVersion,
			}
		} else {
			query = `UPDATE assessment_cycle_members
				SET predecessor_assessment_id = NULLIF($4, ''), relationship_version = $5, archived_at = $6
				WHERE tenant_id = $1 AND cycle_id = $2 AND assessment_id = $3`
			args = []any{
				tenantID.String(),
				member.CycleID.String(),
				member.AssessmentID.String(),
				member.PredecessorAssessmentID.String(),
				member.RelationshipVersion,
				member.ArchivedAt,
			}
		}

		tag, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return mapPostgresError(err, "update assessment cycle member")
		}

		if tag.RowsAffected() == 0 {
			var exists bool
			_ = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assessment_cycle_members WHERE tenant_id = $1 AND cycle_id = $2 AND assessment_id = $3)`, tenantID.String(), member.CycleID.String(), member.AssessmentID.String()).Scan(&exists)
			if !exists {
				return fmt.Errorf("%w: member %q not found in cycle %q", shared.ErrNotFound, member.AssessmentID, member.CycleID)
			}
			return fmt.Errorf("%w: member relationship version mismatch (expected %d)", shared.ErrConflict, expectedVersion)
		}

		return nil
	})
}

func (r *AssessmentCycleRepository) LockCycleForUpdate(ctx context.Context, tenantID, cycleID shared.ID) (*assessmentcycle.AssessmentCycle, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}

	var cycle *assessmentcycle.AssessmentCycle
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		query := `SELECT ` + assessmentCycleCols + ` FROM assessment_cycles WHERE tenant_id = $1 AND id = $2 FOR UPDATE`
		row := tx.QueryRow(ctx, query, tenantID.String(), cycleID.String())
		c, err := scanAssessmentCycle(row)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, cycleID)
			}
			return err
		}
		cycle = c
		return nil
	})
	return cycle, err
}

func scanAssessmentCycle(row rowScanner) (*assessmentcycle.AssessmentCycle, error) {
	var (
		tenantID, id, name, boundaryKind, status string
		businessAssetID, projectID               pgtype.Text
		rootAssessmentID, selectedHeadID         string
		nextRetestNumber                         int
		version                                  int64
		createdAt, updatedAt                     time.Time
		createdBy, updatedBy                     string
		activeManifestID                         pgtype.Text
		activeCycleVersion                       pgtype.Int8
	)

	err := row.Scan(
		&tenantID,
		&id,
		&name,
		&boundaryKind,
		&businessAssetID,
		&projectID,
		&status,
		&rootAssessmentID,
		&selectedHeadID,
		&nextRetestNumber,
		&version,
		&createdAt,
		&updatedAt,
		&createdBy,
		&updatedBy,
		&activeManifestID,
		&activeCycleVersion,
	)
	if err != nil {
		return nil, err
	}

	return &assessmentcycle.AssessmentCycle{
		TenantID:                  shared.ID(tenantID),
		ID:                        shared.ID(id),
		Name:                      name,
		BoundaryKind:              assessmentcycle.BoundaryKind(boundaryKind),
		BusinessAssetID:           shared.ID(businessAssetID.String),
		ProjectID:                 shared.ID(projectID.String),
		Status:                    assessmentcycle.Status(status),
		RootAssessmentID:          shared.ID(rootAssessmentID),
		SelectedHeadAssessmentID:  shared.ID(selectedHeadID),
		NextRetestNumber:          nextRetestNumber,
		Version:                   version,
		CreatedAt:                 createdAt,
		UpdatedAt:                 updatedAt,
		CreatedBy:                 createdBy,
		UpdatedBy:                 updatedBy,
		ActiveClosureManifestID:   shared.ID(activeManifestID.String),
		ActiveClosureCycleVersion: activeCycleVersion.Int64,
	}, nil
}

func scanAssessmentCycleListRecord(row rowScanner, memberLimit int) (*assessmentcycle.AssessmentCycle, ports.AssessmentCycleListRecord, error) {
	var (
		cycle              assessmentcycle.AssessmentCycle
		kind               string
		status             string
		businessAssetID    pgtype.Text
		projectID          pgtype.Text
		latestAssessmentID string
		membersJSON        []byte
		rootSnapshotID     string
		currentSnapshotID  string
		comparisonID       string
		comparisonStatus   string
		comparisonSummary  []byte
		activeManifestID   string
		selectedHeadScanAt pgtype.Timestamptz
		scanStaleness      string
		record             ports.AssessmentCycleListRecord
	)
	err := row.Scan(
		&cycle.TenantID, &cycle.ID, &cycle.Name, &kind, &businessAssetID, &projectID, &status,
		&cycle.RootAssessmentID, &cycle.SelectedHeadAssessmentID, &cycle.NextRetestNumber, &cycle.Version,
		&cycle.CreatedAt, &cycle.UpdatedAt, &cycle.CreatedBy, &cycle.UpdatedBy,
		&record.MemberCount, &record.ActiveBranchCount, &latestAssessmentID, &record.LatestRetestNumber,
		&membersJSON, &rootSnapshotID, &currentSnapshotID, &comparisonID, &comparisonStatus, &comparisonSummary, &activeManifestID,
		&selectedHeadScanAt, &scanStaleness,
	)
	if err != nil {
		return nil, ports.AssessmentCycleListRecord{}, fmt.Errorf("scan assessment cycle list record: %w", err)
	}
	cycle.BoundaryKind, cycle.Status = assessmentcycle.BoundaryKind(kind), assessmentcycle.Status(status)
	if businessAssetID.Valid {
		cycle.BusinessAssetID = shared.ID(businessAssetID.String)
	}
	if projectID.Valid {
		cycle.ProjectID = shared.ID(projectID.String)
	}
	record.LatestAssessmentID = shared.ID(latestAssessmentID)
	var members []assessmentCycleListMemberJSON
	if err := json.Unmarshal(membersJSON, &members); err != nil {
		return nil, ports.AssessmentCycleListRecord{}, fmt.Errorf("decode assessment cycle list members: %w", err)
	}
	record.MembersHaveMore = len(members) > memberLimit
	for _, member := range members[:min(len(members), memberLimit)] {
		record.Members = append(record.Members, assessmentcycle.Member{
			TenantID: cycle.TenantID, CycleID: cycle.ID, AssessmentID: shared.ID(member.AssessmentID), AssessmentType: assessmentcycle.AssessmentType(member.AssessmentType),
			PredecessorAssessmentID: shared.ID(member.PredecessorAssessmentID), RetestNumber: member.RetestNumber, RelationshipVersion: member.RelationshipVersion,
			CreatedAt: member.CreatedAt, CreatedBy: member.CreatedBy, ArchivedAt: member.ArchivedAt,
		})
	}
	record.RootSnapshotID, record.CurrentSnapshotID, record.ComparisonID = shared.ID(rootSnapshotID), shared.ID(currentSnapshotID), shared.ID(comparisonID)
	record.ComparisonStatus, record.ActiveManifestID, record.ScanStaleness = assessmentcomparison.Status(comparisonStatus), shared.ID(activeManifestID), scanStaleness
	if selectedHeadScanAt.Valid {
		scanAt := selectedHeadScanAt.Time.UTC()
		record.SelectedHeadScanAt = &scanAt
	}
	if comparisonID != "" {
		if err := json.Unmarshal(comparisonSummary, &record.ComparisonSummary); err != nil {
			return nil, ports.AssessmentCycleListRecord{}, fmt.Errorf("decode assessment cycle comparison summary: %w", err)
		}
	}
	if err := cycle.Validate(); err != nil {
		return nil, ports.AssessmentCycleListRecord{}, err
	}
	return &cycle, record, nil
}

type assessmentCycleListMemberJSON struct {
	AssessmentID            string     `json:"assessment_id"`
	AssessmentType          string     `json:"assessment_type"`
	PredecessorAssessmentID string     `json:"predecessor_assessment_id"`
	RetestNumber            int        `json:"retest_number"`
	RelationshipVersion     int64      `json:"relationship_version"`
	CreatedAt               time.Time  `json:"created_at"`
	CreatedBy               string     `json:"created_by"`
	ArchivedAt              *time.Time `json:"archived_at"`
}

func nullableCycleCursorTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func scanAssessmentCycleMember(row rowScanner) (*assessmentcycle.Member, error) {
	var (
		tenantID, cycleID, assessmentID, assessmentType string
		predecessorID                                   pgtype.Text
		retestNumber                                    int
		relationshipVersion                             int64
		createdAt                                       time.Time
		createdBy                                       string
		archivedAt                                      *time.Time
	)

	err := row.Scan(
		&tenantID,
		&cycleID,
		&assessmentID,
		&assessmentType,
		&predecessorID,
		&retestNumber,
		&relationshipVersion,
		&createdAt,
		&createdBy,
		&archivedAt,
	)
	if err != nil {
		return nil, err
	}

	return &assessmentcycle.Member{
		TenantID:                shared.ID(tenantID),
		CycleID:                 shared.ID(cycleID),
		AssessmentID:            shared.ID(assessmentID),
		AssessmentType:          assessmentcycle.AssessmentType(assessmentType),
		PredecessorAssessmentID: shared.ID(predecessorID.String),
		RetestNumber:            retestNumber,
		RelationshipVersion:     relationshipVersion,
		CreatedAt:               createdAt,
		CreatedBy:               createdBy,
		ArchivedAt:              archivedAt,
	}, nil
}

func mapPostgresError(err error, op string) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: %s unique constraint violation (%s)", shared.ErrConflict, op, pgErr.ConstraintName)
		case "23503": // foreign_key_violation
			return fmt.Errorf("%w: %s foreign key violation (%s)", shared.ErrNotFound, op, pgErr.ConstraintName)
		case "23514": // check_violation
			return fmt.Errorf("%w: %s check constraint violation (%s)", shared.ErrValidation, op, pgErr.ConstraintName)
		}
	}
	return fmt.Errorf("%s: %w", op, err)
}
