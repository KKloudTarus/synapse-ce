package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const assessmentCycleCols = `tenant_id, id, name, boundary_kind, business_asset_id, project_id, status, root_assessment_id, selected_head_assessment_id, next_retest_number, version, created_at, updated_at, created_by, updated_by`
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
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $10, $11, $12, $13, $14, $15)`

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
				c.created_at, c.updated_at, c.created_by, c.updated_by
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
				    updated_at = $11, updated_by = $12
				WHERE tenant_id = $1 AND id = $2 AND version = $13`
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
				expectedVersion,
			}
		} else {
			query = `UPDATE assessment_cycles
				SET name = $3, boundary_kind = $4, business_asset_id = NULLIF($5, ''), project_id = NULLIF($6, ''),
				    status = $7, selected_head_assessment_id = $8, next_retest_number = $9, version = $10,
				    updated_at = $11, updated_by = $12
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
	)
	if err != nil {
		return nil, err
	}

	return &assessmentcycle.AssessmentCycle{
		TenantID:                 shared.ID(tenantID),
		ID:                       shared.ID(id),
		Name:                     name,
		BoundaryKind:             assessmentcycle.BoundaryKind(boundaryKind),
		BusinessAssetID:          shared.ID(businessAssetID.String),
		ProjectID:                shared.ID(projectID.String),
		Status:                   assessmentcycle.Status(status),
		RootAssessmentID:         shared.ID(rootAssessmentID),
		SelectedHeadAssessmentID: shared.ID(selectedHeadID),
		NextRetestNumber:         nextRetestNumber,
		Version:                  version,
		CreatedAt:                createdAt,
		UpdatedAt:                updatedAt,
		CreatedBy:                createdBy,
		UpdatedBy:                updatedBy,
	}, nil
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
