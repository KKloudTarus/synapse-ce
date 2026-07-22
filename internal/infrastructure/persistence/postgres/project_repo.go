package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const projectCols = `id, tenant_id, name, key, source_binding, default_profile_by_lang, gate_id, created_at, updated_at, created_by, updated_by`

type ProjectRepository struct{ pool *pgxpool.Pool }

func NewProjectRepository(pool *pgxpool.Pool) *ProjectRepository {
	return &ProjectRepository{pool: pool}
}

var _ ports.ProjectRepository = (*ProjectRepository)(nil)

func (r *ProjectRepository) Create(ctx context.Context, p *project.Project) error {
	return insertProject(ctx, r.pool, p)
}

type projectExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertProject(ctx context.Context, execer projectExecer, p *project.Project) error {
	source, err := json.Marshal(p.SourceBinding)
	if err != nil {
		return fmt.Errorf("marshal project source: %w", err)
	}
	profiles, err := json.Marshal(p.DefaultProfileByLang)
	if err != nil {
		return fmt.Errorf("marshal project profiles: %w", err)
	}
	_, err = execer.Exec(ctx, `INSERT INTO projects (`+projectCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		p.ID.String(), p.TenantID.String(), p.Name, p.Key, source, profiles, p.GateID,
		p.Audit.CreatedAt, p.Audit.UpdatedAt, p.Audit.CreatedBy, p.Audit.UpdatedBy)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("project key %q already exists: %w", p.Key, shared.ErrConflict)
		}
		return fmt.Errorf("insert project: %w", err)
	}
	return nil
}

func (r *ProjectRepository) List(ctx context.Context, tenantID shared.ID) ([]*project.Project, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if tenantID.IsZero() {
		rows, err = r.pool.Query(ctx, `SELECT `+projectCols+` FROM projects ORDER BY created_at DESC, key`)
	} else {
		rows, err = r.pool.Query(ctx, `SELECT `+projectCols+` FROM projects WHERE tenant_id=$1 ORDER BY created_at DESC, key`, tenantID.String())
	}
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()
	out := make([]*project.Project, 0)
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *ProjectRepository) GetByKey(ctx context.Context, tenantID shared.ID, key string) (*project.Project, error) {
	var row pgx.Row
	if tenantID.IsZero() {
		row = r.pool.QueryRow(ctx, `SELECT `+projectCols+` FROM projects WHERE key=$1 ORDER BY created_at, id LIMIT 1`, key)
	} else {
		row = r.pool.QueryRow(ctx, `SELECT `+projectCols+` FROM projects WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key)
	}
	p, err := scanProject(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select project: %w", err)
	}
	return p, nil
}

func (r *ProjectRepository) GetByID(ctx context.Context, tenantID, projectID shared.ID) (*project.Project, error) {
	var row pgx.Row
	if tenantID.IsZero() {
		row = r.pool.QueryRow(ctx, `SELECT `+projectCols+` FROM projects WHERE id=$1`, projectID.String())
	} else {
		row = r.pool.QueryRow(ctx, `SELECT `+projectCols+` FROM projects WHERE tenant_id=$1 AND id=$2`, tenantID.String(), projectID.String())
	}
	p, err := scanProject(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select project: %w", err)
	}
	return p, nil
}

func (r *ProjectRepository) UpdateGate(ctx context.Context, tenantID shared.ID, key, gateID string) error {
	ct, err := r.pool.Exec(ctx, `UPDATE projects SET gate_id=$3, updated_at=now() WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key, gateID)
	if err != nil {
		return fmt.Errorf("update project gate: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// AssignProfile sets or clears the quality profile for a language in the project's JSONB
// default_profile_by_lang map, atomically at the column level (no read-modify-write race).
func (r *ProjectRepository) AssignProfile(ctx context.Context, tenantID shared.ID, projectKey, language, profileKey string) error {
	var (
		ct  pgconn.CommandTag
		err error
	)
	if strings.TrimSpace(profileKey) == "" {
		ct, err = r.pool.Exec(ctx, `UPDATE projects SET default_profile_by_lang = coalesce(default_profile_by_lang, '{}'::jsonb) - $3::text, updated_at=now() WHERE tenant_id=$1 AND key=$2`,
			tenantID.String(), projectKey, language)
	} else {
		ct, err = r.pool.Exec(ctx, `UPDATE projects SET default_profile_by_lang = jsonb_set(coalesce(default_profile_by_lang, '{}'::jsonb), ARRAY[$3::text], to_jsonb($4::text), true), updated_at=now() WHERE tenant_id=$1 AND key=$2`,
			tenantID.String(), projectKey, language, profileKey)
	}
	if err != nil {
		return fmt.Errorf("assign project profile: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return shared.ErrNotFound
	}
	return nil
}

func (r *ProjectRepository) CountByGate(ctx context.Context, tenantID shared.ID, gateID string) (int, error) {
	var n int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM projects WHERE tenant_id=$1 AND gate_id=$2`, tenantID.String(), gateID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count projects by gate: %w", err)
	}
	return n, nil
}

func (r *ProjectRepository) DeleteByKey(ctx context.Context, tenantID shared.ID, key string) error {
	var (
		ct  pgconn.CommandTag
		err error
	)
	if tenantID.IsZero() {
		ct, err = r.pool.Exec(ctx, `DELETE FROM projects WHERE id=(SELECT id FROM projects WHERE key=$1 ORDER BY created_at, id LIMIT 1)`, key)
	} else {
		ct, err = r.pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1 AND key=$2`, tenantID.String(), key)
	}
	if err != nil {
		return fmt.Errorf("delete project: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return shared.ErrNotFound
	}
	return nil
}

func scanProject(row rowScanner) (*project.Project, error) {
	var (
		p                    project.Project
		id, tenant           string
		sourceJSON, profiles []byte
	)
	if err := row.Scan(&id, &tenant, &p.Name, &p.Key, &sourceJSON, &profiles, &p.GateID,
		&p.Audit.CreatedAt, &p.Audit.UpdatedAt, &p.Audit.CreatedBy, &p.Audit.UpdatedBy); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(sourceJSON, &p.SourceBinding); err != nil {
		return nil, fmt.Errorf("unmarshal project source: %w", err)
	}
	if err := json.Unmarshal(profiles, &p.DefaultProfileByLang); err != nil {
		return nil, fmt.Errorf("unmarshal project profiles: %w", err)
	}
	p.ID, p.TenantID = shared.ID(id), shared.ID(tenant)
	return &p, nil
}
