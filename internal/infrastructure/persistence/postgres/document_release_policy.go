package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
)

type DocumentSourceReleaseReader struct{ pool *pgxpool.Pool }

var _ ports.DocumentSourceReleaseReader = (*DocumentSourceReleaseReader)(nil)

func NewDocumentSourceReleaseReader(pool *pgxpool.Pool) (*DocumentSourceReleaseReader, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: document source policy requires PostgreSQL", shared.ErrValidation)
	}
	return &DocumentSourceReleaseReader{pool: pool}, nil
}

func (s *DocumentSourceReleaseReader) CheckDocumentSource(ctx context.Context, tenant shared.ID, target docpublish.Target) error {
	if err := target.Validate(); err != nil {
		return err
	}
	return s.CheckReportSource(ctx, tenant, target.Source())
}

func (s *DocumentSourceReleaseReader) CheckReportSource(ctx context.Context, tenant shared.ID, target docpublish.Source) error {
	if tenant.IsZero() {
		return shared.ErrValidation
	}
	if err := target.Validate(); err != nil {
		return err
	}
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var query string
		switch target.SourceKind {
		case docpublish.EngagementReport:
			if target.SourceRef != "engagement:"+target.ScopeID.String() {
				return shared.ErrValidation
			}
			var status string
			if err := tx.QueryRow(ctx, `SELECT status FROM engagements WHERE tenant_id=$1 AND id=$2 AND project_id IS NULL AND host_asset_id IS NULL`, tenant.String(), target.ScopeID.String()).Scan(&status); err != nil {
				return err
			}
			if status != "active" && status != "completed" {
				return shared.ErrForbidden
			}
			query = `SELECT e.id FROM engagements e WHERE e.tenant_id=$1 AND e.id=$2`
		case docpublish.ProjectQualitySummary:
			if target.SourceRef != "project:"+target.ScopeID.String() {
				return shared.ErrValidation
			}
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE tenant_id=$1 AND id=$2)`, tenant.String(), target.ScopeID.String()).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return shared.ErrNotFound
			}
			query = `SELECT e.id FROM engagements e WHERE e.tenant_id=$1 AND (e.project_id=$2 OR e.assessment_project_id=$2)`
		case docpublish.AssessmentClosureReport:
			if !strings.HasPrefix(target.SourceRef, "assessment-cycle:") {
				return shared.ErrValidation
			}
			var status, project, manifest string
			if err := tx.QueryRow(ctx, `SELECT status,COALESCE(project_id,''),COALESCE(active_closure_manifest_id,'') FROM assessment_cycles WHERE tenant_id=$1 AND id=$2`, tenant.String(), strings.TrimPrefix(target.SourceRef, "assessment-cycle:")).Scan(&status, &project, &manifest); err != nil {
				return err
			}
			if project != target.ScopeID.String() {
				return shared.ErrNotFound
			}
			if status != "completed" || manifest == "" {
				return shared.ErrForbidden
			}
			query = `SELECT m.assessment_id FROM assessment_cycle_members m WHERE m.tenant_id=$1 AND m.cycle_id=$2`
		default:
			return shared.ErrValidation
		}
		selector := target.ScopeID.String()
		if target.SourceKind == docpublish.AssessmentClosureReport {
			selector = strings.TrimPrefix(target.SourceRef, "assessment-cycle:")
		}
		rows, err := tx.Query(ctx, query+` ORDER BY 1 LIMIT 1001`, tenant.String(), selector)
		if err != nil {
			return err
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(ids) == 0 || len(ids) > 1000 {
			return shared.ErrForbidden
		}
		var blocked bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM legal_holds WHERE tenant_id=$1 AND engagement_id=ANY($2) AND released_at IS NULL) OR EXISTS(SELECT 1 FROM notification_engagement_settings WHERE tenant_id=$1 AND engagement_id=ANY($2) AND external_notifications<>'inherit')`, tenant.String(), ids).Scan(&blocked)
		if err != nil {
			return err
		}
		if blocked {
			return shared.ErrForbidden
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return shared.ErrNotFound
	}
	return err
}
