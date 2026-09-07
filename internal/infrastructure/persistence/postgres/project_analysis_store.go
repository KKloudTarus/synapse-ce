package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ProjectAnalysisStore persists immutable Project analysis snapshots and, through the hotspot and
// issue files in this package, their projections. project_analyses and every projection table are
// RLS-protected (migration 0129), so each statement runs inside requireTenant and keeps its own
// tenant_id predicate.
//
// The pre-0129 reads branched to a tenant-free WHERE whenever the caller passed a zero tenant,
// which widened the query instead of denying it. Those branches are gone: a missing tenant is a
// validation error.
type ProjectAnalysisStore struct{ pool *pgxpool.Pool }

func NewProjectAnalysisStore(pool *pgxpool.Pool) *ProjectAnalysisStore {
	return &ProjectAnalysisStore{pool: pool}
}

var _ ports.ProjectAnalysisStore = (*ProjectAnalysisStore)(nil)

func (r *ProjectAnalysisStore) Save(ctx context.Context, analysis projectanalysis.Analysis) error {
	return r.SaveWithResult(ctx, analysis, nil)
}

func (r *ProjectAnalysisStore) SaveWithResult(ctx context.Context, analysis projectanalysis.Analysis, result []byte) error {
	payload, err := json.Marshal(analysis)
	if err != nil {
		return fmt.Errorf("marshal project analysis: %w", err)
	}
	return requireTenant(ctx, r.pool, shared.ID(analysis.TenantID), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO project_analyses (id, tenant_id, project_id, branch, created_at, payload, result)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`,
			analysis.ID, analysis.TenantID, analysis.ProjectID, analysis.Branch(), analysis.CreatedAt, payload, result); err != nil {
			return fmt.Errorf("insert project analysis: %w", err)
		}
		return nil
	})
}

func (r *ProjectAnalysisStore) LatestForProjects(ctx context.Context, tenantID shared.ID, projectIDs []shared.ID) (map[shared.ID]projectanalysis.Analysis, error) {
	ids := make([]string, len(projectIDs))
	for i, id := range projectIDs {
		ids[i] = id.String()
	}
	if len(ids) == 0 {
		return map[shared.ID]projectanalysis.Analysis{}, nil
	}
	out := map[shared.ID]projectanalysis.Analysis{}
	if err := requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (project_id) project_id, payload FROM project_analyses WHERE tenant_id=$1 AND project_id = ANY($2) ORDER BY project_id, created_at DESC, id COLLATE "C" DESC`, tenantID.String(), ids)
		if err != nil {
			return fmt.Errorf("list latest project analyses: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var payload []byte
			if err := rows.Scan(&id, &payload); err != nil {
				return fmt.Errorf("scan latest project analysis: %w", err)
			}
			var analysis projectanalysis.Analysis
			if err := json.Unmarshal(payload, &analysis); err != nil {
				return fmt.Errorf("decode project analysis: %w", err)
			}
			out[shared.ID(id)] = analysis
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *ProjectAnalysisStore) LatestWithResult(ctx context.Context, tenantID, projectID shared.ID, branch string) (projectanalysis.Analysis, []byte, error) {
	var (
		analysis projectanalysis.Analysis
		result   []byte
	)
	if err := requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		var payload []byte
		query := `SELECT payload, result FROM project_analyses WHERE tenant_id=$1 AND project_id=$2 AND result IS NOT NULL`
		args := []any{tenantID.String(), projectID.String()}
		if branch != "" {
			query += ` AND branch=$3`
			args = append(args, branch)
		}
		query += ` ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT 1`
		err := tx.QueryRow(ctx, query, args...).
			Scan(&payload, &result)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("latest project analysis: %w", err)
		}
		if err := json.Unmarshal(payload, &analysis); err != nil {
			return fmt.Errorf("decode project analysis: %w", err)
		}
		return nil
	}); err != nil {
		return projectanalysis.Analysis{}, nil, err
	}
	return analysis, result, nil
}

func (r *ProjectAnalysisStore) List(ctx context.Context, tenantID, projectID shared.ID, branch string, limit int, beforeCreatedAt time.Time, beforeID shared.ID) ([]projectanalysis.Analysis, bool, error) {
	cursor := beforeCreatedAt
	if beforeCreatedAt.IsZero() {
		cursor = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	}
	out := make([]projectanalysis.Analysis, 0, limit+1)
	if err := requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		query := `SELECT payload FROM project_analyses
			WHERE tenant_id=$1 AND project_id=$2 AND (created_at < $3 OR (created_at = $3 AND id COLLATE "C" < $4))`
		args := []any{tenantID.String(), projectID.String(), cursor, beforeID.String()}
		if branch != "" {
			args = append(args, branch)
			query += fmt.Sprintf(" AND branch=$%d", len(args))
		}
		args = append(args, limit+1)
		query += fmt.Sprintf(` ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT $%d`, len(args))
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("list project analyses: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			analysis, err := scanProjectAnalysis(rows)
			if err != nil {
				return err
			}
			out = append(out, analysis)
		}
		return rows.Err()
	}); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// Branches returns the distinct branch values recorded for the project, sorted.
func (r *ProjectAnalysisStore) Branches(ctx context.Context, tenantID, projectID shared.ID) ([]string, error) {
	out := make([]string, 0)
	if err := requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT branch FROM project_analyses WHERE tenant_id=$1 AND project_id=$2 ORDER BY branch`, tenantID.String(), projectID.String())
		if err != nil {
			return fmt.Errorf("list project analysis branches: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var branch string
			if err := rows.Scan(&branch); err != nil {
				return fmt.Errorf("scan project analysis branch: %w", err)
			}
			out = append(out, branch)
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *ProjectAnalysisStore) Get(ctx context.Context, tenantID, projectID, analysisID shared.ID) (projectanalysis.Analysis, error) {
	var analysis projectanalysis.Analysis
	if err := requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		found, err := scanProjectAnalysis(tx.QueryRow(ctx, `SELECT payload FROM project_analyses WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, tenantID.String(), projectID.String(), analysisID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get project analysis: %w", err)
		}
		analysis = found
		return nil
	}); err != nil {
		return projectanalysis.Analysis{}, err
	}
	return analysis, nil
}

func scanProjectAnalysis(row rowScanner) (projectanalysis.Analysis, error) {
	var payload []byte
	if err := row.Scan(&payload); err != nil {
		return projectanalysis.Analysis{}, err
	}
	var analysis projectanalysis.Analysis
	if err := json.Unmarshal(payload, &analysis); err != nil {
		return projectanalysis.Analysis{}, fmt.Errorf("decode project analysis: %w", err)
	}
	return analysis, nil
}
