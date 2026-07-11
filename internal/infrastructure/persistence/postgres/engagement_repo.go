package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const engagementCols = `id, tenant_id, name, client, status, authorized_from, authorized_to, created_at, updated_at, timezone, roe, live_recon, created_by, updated_by`

// EngagementRepository persists engagements and their scope to PostgreSQL.
type EngagementRepository struct{ pool *pgxpool.Pool }

// NewEngagementRepository returns a repository backed by the given pool.
func NewEngagementRepository(pool *pgxpool.Pool) *EngagementRepository {
	return &EngagementRepository{pool: pool}
}

var _ ports.EngagementRepository = (*EngagementRepository)(nil)

// Create inserts the engagement and its scope targets in one transaction.
func (r *EngagementRepository) Create(ctx context.Context, e *engagement.Engagement) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	roeJSON, err := json.Marshal(e.RoE)
	if err != nil {
		return fmt.Errorf("marshal roe: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO engagements (`+engagementCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		e.ID.String(), e.TenantID.String(), e.Name, e.Client, string(e.Status),
		e.AuthorizedFrom, e.AuthorizedTo, e.Audit.CreatedAt, e.Audit.UpdatedAt, e.Timezone, roeJSON, e.LiveReconEnabled,
		e.Audit.CreatedBy, e.Audit.UpdatedBy); err != nil {
		return fmt.Errorf("insert engagement: %w", err)
	}

	// Insert-only path: deterministic scope_target PKs are fine here. A future
	// "replace scope" path should switch to generated IDs (IDGenerator / gen_random_uuid).
	i := 0
	insert := func(targets []engagement.Target, inScope bool) error {
		for _, t := range targets {
			stID := e.ID.String() + "-st-" + strconv.Itoa(i)
			i++
			if _, err := tx.Exec(ctx,
				`INSERT INTO scope_targets (id, engagement_id, in_scope, kind, value) VALUES ($1,$2,$3,$4,$5)`,
				stID, e.ID.String(), inScope, string(t.Kind), t.Value); err != nil {
				return fmt.Errorf("insert scope target: %w", err)
			}
		}
		return nil
	}
	if err := insert(e.Scope.InScope, true); err != nil {
		return err
	}
	if err := insert(e.Scope.OutOfScope, false); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Update persists an existing engagement aggregate: the engagement row and its
// full scope target set, replaced atomically in one transaction (E1 scope CRUD +
// lifecycle). Returns shared.ErrNotFound if the engagement does not exist. Unlike
// Create's deterministic scope PKs, the replace path uses generated IDs.
func (r *EngagementRepository) Update(ctx context.Context, e *engagement.Engagement) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	roeJSON, err := json.Marshal(e.RoE)
	if err != nil {
		return fmt.Errorf("marshal roe: %w", err)
	}
	// created_by is intentionally NOT updated – the owner is immutable; only updated_by changes.
	ct, err := tx.Exec(ctx,
		`UPDATE engagements SET name=$2, client=$3, status=$4, authorized_from=$5, authorized_to=$6, timezone=$7, updated_at=$8, roe=$9, live_recon=$10, updated_by=$11 WHERE id=$1`,
		e.ID.String(), e.Name, e.Client, string(e.Status),
		e.AuthorizedFrom, e.AuthorizedTo, e.Timezone, e.Audit.UpdatedAt, roeJSON, e.LiveReconEnabled, e.Audit.UpdatedBy)
	if err != nil {
		return fmt.Errorf("update engagement: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return shared.ErrNotFound
	}

	// Replace the scope atomically: clear then re-insert with generated PKs.
	if _, err := tx.Exec(ctx, `DELETE FROM scope_targets WHERE engagement_id=$1`, e.ID.String()); err != nil {
		return fmt.Errorf("clear scope: %w", err)
	}
	insert := func(targets []engagement.Target, inScope bool) error {
		for _, t := range targets {
			if _, err := tx.Exec(ctx,
				`INSERT INTO scope_targets (id, engagement_id, in_scope, kind, value) VALUES (gen_random_uuid()::text,$1,$2,$3,$4)`,
				e.ID.String(), inScope, string(t.Kind), t.Value); err != nil {
				return fmt.Errorf("insert scope target: %w", err)
			}
		}
		return nil
	}
	if err := insert(e.Scope.InScope, true); err != nil {
		return err
	}
	if err := insert(e.Scope.OutOfScope, false); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Delete removes an engagement; ON DELETE CASCADE drops its scope, findings,
// comments, evidence, recon runs, and retests. Idempotent (no error if absent).
// Used to roll back a partially-materialized import.
func (r *EngagementRepository) Delete(ctx context.Context, id shared.ID) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM engagements WHERE id=$1`, id.String()); err != nil {
		return fmt.Errorf("delete engagement: %w", err)
	}
	return nil
}

// GetByID returns the engagement with its full scope WITHOUT a tenant predicate. It is the
// INTERNAL execution-gate read (see ports.EngagementRepository.GetByID): the scope/window/RoE
// guard and the worker/agent execution paths, which act on an engagement a queued/authorized run
// already belongs to. User-facing access uses GetByIDInTenant (below), which adds the tenant
// predicate that blocks cross-tenant reads.
func (r *EngagementRepository) GetByID(ctx context.Context, id shared.ID) (*engagement.Engagement, error) {
	e, err := scanEngagement(r.pool.QueryRow(ctx,
		`SELECT `+engagementCols+` FROM engagements WHERE id=$1`, id.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select engagement: %w", err)
	}
	scope, err := r.loadScope(ctx, id)
	if err != nil {
		return nil, err
	}
	e.Scope = scope
	return e, nil
}

// GetByIDInTenant loads an engagement scoped to tenantID (tenant isolation). A caller
// tenant of ” (single-tenant / default-tenant admin) matches any row; a non-empty tenant
// matches only its own – tenant A cannot read tenant B's engagement (ErrNotFound, existence
// not revealed).
func (r *EngagementRepository) GetByIDInTenant(ctx context.Context, tenantID, id shared.ID) (*engagement.Engagement, error) {
	e, err := scanEngagement(r.pool.QueryRow(ctx,
		`SELECT `+engagementCols+` FROM engagements WHERE id=$1 AND (tenant_id=$2 OR $2='')`,
		id.String(), tenantID.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select engagement: %w", err)
	}
	scope, err := r.loadScope(ctx, id)
	if err != nil {
		return nil, err
	}
	e.Scope = scope
	return e, nil
}

// List returns the tenant's engagements, each with its scope loaded (consistent
// with the in-memory repository; the UI and the scope gate both rely on scope).
func (r *EngagementRepository) List(ctx context.Context, tenantID shared.ID) ([]*engagement.Engagement, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if tenantID.IsZero() {
		rows, err = r.pool.Query(ctx, `SELECT `+engagementCols+` FROM engagements ORDER BY created_at DESC`)
	} else {
		rows, err = r.pool.Query(ctx, `SELECT `+engagementCols+` FROM engagements WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID.String())
	}
	if err != nil {
		return nil, fmt.Errorf("list engagements: %w", err)
	}
	defer rows.Close()

	out := make([]*engagement.Engagement, 0)
	for rows.Next() {
		e, err := scanEngagement(rows)
		if err != nil {
			return nil, fmt.Errorf("scan engagement: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list engagements: %w", err)
	}
	// Rows are exhausted (auto-closed) here, so the pool conn is free to load scope.
	for _, e := range out {
		scope, err := r.loadScope(ctx, e.ID)
		if err != nil {
			return nil, err
		}
		e.Scope = scope
	}
	return out, nil
}

func (r *EngagementRepository) loadScope(ctx context.Context, id shared.ID) (engagement.Scope, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT in_scope, kind, value FROM scope_targets WHERE engagement_id=$1 ORDER BY id`, id.String())
	if err != nil {
		return engagement.Scope{}, fmt.Errorf("select scope: %w", err)
	}
	defer rows.Close()

	var scope engagement.Scope
	for rows.Next() {
		var (
			inScope     bool
			kind, value string
		)
		if err := rows.Scan(&inScope, &kind, &value); err != nil {
			return engagement.Scope{}, fmt.Errorf("scan scope: %w", err)
		}
		t := engagement.Target{Kind: engagement.TargetKind(kind), Value: value}
		if inScope {
			scope.InScope = append(scope.InScope, t)
		} else {
			scope.OutOfScope = append(scope.OutOfScope, t)
		}
	}
	return scope, rows.Err()
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanEngagement(row rowScanner) (*engagement.Engagement, error) {
	var (
		e              engagement.Engagement
		idStr, ten, st string
		af, at         pgtype.Timestamptz
		roeJSON        []byte
	)
	if err := row.Scan(&idStr, &ten, &e.Name, &e.Client, &st, &af, &at, &e.Audit.CreatedAt, &e.Audit.UpdatedAt, &e.Timezone, &roeJSON, &e.LiveReconEnabled, &e.Audit.CreatedBy, &e.Audit.UpdatedBy); err != nil {
		return nil, err
	}
	if len(roeJSON) > 0 {
		if err := json.Unmarshal(roeJSON, &e.RoE); err != nil {
			return nil, fmt.Errorf("unmarshal roe: %w", err)
		}
	}
	e.ID = shared.ID(idStr)
	e.TenantID = shared.ID(ten)
	e.Status = engagement.Status(st)
	if af.Valid {
		t := af.Time
		e.AuthorizedFrom = &t
	}
	if at.Valid {
		t := at.Time
		e.AuthorizedTo = &t
	}
	return &e, nil
}
