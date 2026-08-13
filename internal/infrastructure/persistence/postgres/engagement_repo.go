package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const engagementCols = `id, tenant_id, project_id, business_asset_id, name, client, status, authorized_from, authorized_to, created_at, updated_at, timezone, roe, live_recon, created_by, updated_by`

// EngagementRepository persists engagements and their scope to PostgreSQL.
type EngagementRepository struct{ pool *pgxpool.Pool }

// NewEngagementRepository returns a repository backed by the given pool.
func NewEngagementRepository(pool *pgxpool.Pool) *EngagementRepository {
	return &EngagementRepository{pool: pool}
}

var _ ports.EngagementRepository = (*EngagementRepository)(nil)
var _ ports.PromotionReconciliationScopeReader = (*EngagementRepository)(nil)
var _ ports.VulnerabilityReconciliationTenantStore = (*EngagementRepository)(nil)

// Create inserts the engagement and its scope targets in one transaction.
func (r *EngagementRepository) Create(ctx context.Context, e *engagement.Engagement) error {
	tenantID := shared.TenantOrDefault(e.TenantID)
	e.TenantID = tenantID
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		roeJSON, err := json.Marshal(e.RoE)
		if err != nil {
			return fmt.Errorf("marshal roe: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO engagements (`+engagementCols+`) VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			e.ID.String(), tenantID.String(), e.ProjectID.String(), e.BusinessAssetID.String(), e.Name, e.Client, string(e.Status),
			e.AuthorizedFrom, e.AuthorizedTo, e.Audit.CreatedAt, e.Audit.UpdatedAt, e.Timezone, roeJSON, e.LiveReconEnabled,
			e.Audit.CreatedBy, e.Audit.UpdatedBy); err != nil {
			return fmt.Errorf("insert engagement: %w", err)
		}

		i := 0
		insert := func(targets []engagement.Target, inScope bool) error {
			for _, target := range targets {
				stID := e.ID.String() + "-st-" + strconv.Itoa(i)
				i++
				if _, err := tx.Exec(ctx,
					`INSERT INTO scope_targets (id, tenant_id, engagement_id, in_scope, kind, value) VALUES ($1,$2,$3,$4,$5,$6)`,
					stID, tenantID.String(), e.ID.String(), inScope, string(target.Kind), target.Value); err != nil {
					return fmt.Errorf("insert scope target: %w", err)
				}
			}
			return nil
		}
		if err := insert(e.Scope.InScope, true); err != nil {
			return err
		}
		return insert(e.Scope.OutOfScope, false)
	})
}

// Update persists an existing engagement aggregate: the engagement row and its
// full scope target set, replaced atomically in one transaction (E1 scope CRUD +
// lifecycle). Returns shared.ErrNotFound if the engagement does not exist. Unlike
// Create's deterministic scope PKs, the replace path uses generated IDs.
func (r *EngagementRepository) ProjectContexts(ctx context.Context, tenantID shared.ID, projectIDs []shared.ID) (out map[shared.ID]*engagement.Engagement, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	ids := make([]string, len(projectIDs))
	for i, id := range projectIDs {
		ids[i] = id.String()
	}
	if len(ids) == 0 {
		return map[shared.ID]*engagement.Engagement{}, nil
	}
	out = map[shared.ID]*engagement.Engagement{}
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+engagementCols+` FROM engagements WHERE tenant_id=$1 AND project_id = ANY($2)`, tenantID.String(), ids)
		if err != nil {
			return fmt.Errorf("list project contexts: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			e, err := scanEngagement(rows)
			if err != nil {
				return err
			}
			out[e.ProjectID] = e
		}
		return rows.Err()
	})
	return out, err
}

func (r *EngagementRepository) Update(ctx context.Context, e *engagement.Engagement) error {
	tenantID := shared.TenantOrDefault(e.TenantID)
	e.TenantID = tenantID
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		roeJSON, err := json.Marshal(e.RoE)
		if err != nil {
			return fmt.Errorf("marshal roe: %w", err)
		}
		ct, err := tx.Exec(ctx,
			`UPDATE engagements SET name=$2, client=$3, status=$4, authorized_from=$5, authorized_to=$6, timezone=$7, updated_at=$8, roe=$9, live_recon=$10, updated_by=$11, business_asset_id=NULLIF($12,'') WHERE id=$1`,
			e.ID.String(), e.Name, e.Client, string(e.Status),
			e.AuthorizedFrom, e.AuthorizedTo, e.Timezone, e.Audit.UpdatedAt, roeJSON, e.LiveReconEnabled, e.Audit.UpdatedBy, e.BusinessAssetID.String())
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
			for _, target := range targets {
				if _, err := tx.Exec(ctx,
					`INSERT INTO scope_targets (id, tenant_id, engagement_id, in_scope, kind, value) VALUES (gen_random_uuid()::text,$1,$2,$3,$4,$5)`,
					tenantID.String(), e.ID.String(), inScope, string(target.Kind), target.Value); err != nil {
					return fmt.Errorf("insert scope target: %w", err)
				}
			}
			return nil
		}
		if err := insert(e.Scope.InScope, true); err != nil {
			return err
		}
		return insert(e.Scope.OutOfScope, false)
	})
}

// Delete removes an engagement; ON DELETE CASCADE drops its scope, findings,
// comments, evidence, recon runs, and retests. Idempotent (no error if absent).
// Used to roll back a partially-materialized import.
func (r *EngagementRepository) Delete(ctx context.Context, id shared.ID) error {
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM engagements WHERE id=$1`, id.String()); err != nil {
			return fmt.Errorf("delete engagement: %w", err)
		}
		return nil
	})
}

// GetByID returns the engagement with its full scope WITHOUT a tenant predicate. It is the
// INTERNAL execution-gate read (see ports.EngagementRepository.GetByID): the scope/window/RoE
// guard and the worker/agent execution paths, which act on an engagement a queued/authorized run
// already belongs to. User-facing access uses GetByIDInTenant (below), which adds the tenant
// predicate that blocks cross-tenant reads.
func (r *EngagementRepository) GetByID(ctx context.Context, id shared.ID) (out *engagement.Engagement, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		out, err = r.get(ctx, tx, `id=$1`, id.String())
		return err
	})
	return out, err
}

// GetByIDInTenant loads an engagement scoped to tenantID. Empty input normalizes to the non-empty
// default tenant and never becomes a wildcard; cross-tenant access returns ErrNotFound.
func (r *EngagementRepository) GetByIDInTenant(ctx context.Context, tenantID, id shared.ID) (out *engagement.Engagement, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		out, err = r.get(ctx, tx, `id=$1 AND project_id IS NULL AND tenant_id=$2`, id.String(), tenantID.String())
		return err
	})
	return out, err
}

func (r *EngagementRepository) GetByProjectID(ctx context.Context, tenantID, projectID shared.ID) (out *engagement.Engagement, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		out, err = r.get(ctx, tx, `project_id=$1 AND tenant_id=$2`, projectID.String(), tenantID.String())
		return err
	})
	return out, err
}

// ListPromotionReconciliationScopes returns every non-project tenant and engagement
// pair for process-local recovery. Each engagement query remains RLS-scoped.
func (r *EngagementRepository) ListPromotionReconciliationScopes(ctx context.Context) ([]ports.PromotionReconciliationScope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenants, err := r.pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list promotion reconciliation tenants: %w", err)
	}
	defer tenants.Close()
	var out []ports.PromotionReconciliationScope
	for tenants.Next() {
		var tenantID shared.ID
		if err := tenants.Scan(&tenantID); err != nil {
			return nil, fmt.Errorf("scan promotion reconciliation tenant: %w", err)
		}
		if err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT id FROM engagements WHERE project_id IS NULL ORDER BY id`)
			if err != nil {
				return fmt.Errorf("list promotion reconciliation engagements: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				var engagementID shared.ID
				if err := rows.Scan(&engagementID); err != nil {
					return fmt.Errorf("scan promotion reconciliation engagement: %w", err)
				}
				out = append(out, ports.PromotionReconciliationScope{TenantID: tenantID, EngagementID: engagementID})
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("list promotion reconciliation engagements: %w", err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if err := tenants.Err(); err != nil {
		return nil, fmt.Errorf("list promotion reconciliation tenants: %w", err)
	}
	return out, nil
}

// List returns the tenant's engagements, each with its scope loaded (consistent
// with the in-memory repository; the UI and the scope gate both rely on scope).
func (r *EngagementRepository) List(ctx context.Context, tenantID shared.ID) (out []*engagement.Engagement, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+engagementCols+` FROM engagements WHERE tenant_id=$1 AND project_id IS NULL ORDER BY created_at DESC`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list engagements: %w", err)
		}
		for rows.Next() {
			e, err := scanEngagement(rows)
			if err != nil {
				rows.Close()
				return fmt.Errorf("scan engagement: %w", err)
			}
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("list engagements: %w", err)
		}
		rows.Close()
		for _, e := range out {
			scope, err := loadScope(ctx, tx, e.ID)
			if err != nil {
				return err
			}
			e.Scope = scope
		}
		return nil
	})
	return out, err
}

// ListProjectEngagements returns the tenant's hidden Project analysis contexts for operational
// aggregation. Normal engagement lists remain unchanged and continue to hide these rows.
func (r *EngagementRepository) ListProjectEngagements(ctx context.Context, tenantID shared.ID) (out []*engagement.Engagement, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+engagementCols+` FROM engagements WHERE tenant_id=$1 AND project_id IS NOT NULL ORDER BY created_at DESC`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list project engagements: %w", err)
		}
		for rows.Next() {
			e, err := scanEngagement(rows)
			if err != nil {
				rows.Close()
				return fmt.Errorf("scan project engagement: %w", err)
			}
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("list project engagements: %w", err)
		}
		rows.Close()
		for _, e := range out {
			scope, err := loadScope(ctx, tx, e.ID)
			if err != nil {
				return err
			}
			e.Scope = scope
		}
		return nil
	})
	return out, err
}

func (r *EngagementRepository) ListTenantIDs(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list vulnerability reconciliation tenants: %w", err)
	}
	defer rows.Close()
	out := make([]shared.ID, 0)
	for rows.Next() {
		var tenantID shared.ID
		if err := rows.Scan(&tenantID); err != nil {
			return nil, fmt.Errorf("scan vulnerability reconciliation tenant: %w", err)
		}
		out = append(out, tenantID)
	}
	return out, rows.Err()
}

func (r *EngagementRepository) ListReconciliationEngagements(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, limit int) (ports.ReconciliationEngagementPage, error) {
	if snapshotAt.IsZero() {
		return ports.ReconciliationEngagementPage{}, fmt.Errorf("%w: reconciliation snapshot time is required", shared.ErrValidation)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	tenantID = shared.TenantOrDefault(tenantID)
	page := ports.ReconciliationEngagementPage{}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM engagements WHERE tenant_id=$1 AND id>$2 AND created_at<=$3 ORDER BY id COLLATE "C" LIMIT $4`, tenantID.String(), after.String(), snapshotAt, limit+1)
		if err != nil {
			return fmt.Errorf("list reconciliation engagements: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id shared.ID
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan reconciliation engagement: %w", err)
			}
			page.IDs = append(page.IDs, id)
		}
		return rows.Err()
	})
	if err != nil {
		return ports.ReconciliationEngagementPage{}, err
	}
	if len(page.IDs) > limit {
		page.IDs = page.IDs[:limit]
		page.Next = page.IDs[len(page.IDs)-1]
	}
	return page, nil
}

func (r *EngagementRepository) get(ctx context.Context, tx pgx.Tx, predicate string, args ...any) (*engagement.Engagement, error) {
	e, err := scanEngagement(tx.QueryRow(ctx, `SELECT `+engagementCols+` FROM engagements WHERE `+predicate, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select engagement: %w", err)
	}
	e.Scope, err = loadScope(ctx, tx, e.ID)
	return e, err
}

func loadScope(ctx context.Context, tx pgx.Tx, id shared.ID) (engagement.Scope, error) {
	rows, err := tx.Query(ctx,
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
		normalized, err := engagement.NormalizeTarget(t, true)
		if err != nil {
			return engagement.Scope{}, fmt.Errorf("normalize stored scope target kind=%q value=%q: %w", kind, value, err)
		}
		if inScope {
			scope.InScope = append(scope.InScope, normalized)
		} else {
			scope.OutOfScope = append(scope.OutOfScope, normalized)
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
		e                          engagement.Engagement
		idStr, ten, st             string
		projectID, businessAssetID pgtype.Text
		af, at                     pgtype.Timestamptz
		roeJSON                    []byte
	)
	if err := row.Scan(&idStr, &ten, &projectID, &businessAssetID, &e.Name, &e.Client, &st, &af, &at, &e.Audit.CreatedAt, &e.Audit.UpdatedAt, &e.Timezone, &roeJSON, &e.LiveReconEnabled, &e.Audit.CreatedBy, &e.Audit.UpdatedBy); err != nil {
		return nil, err
	}
	if len(roeJSON) > 0 {
		if err := json.Unmarshal(roeJSON, &e.RoE); err != nil {
			return nil, fmt.Errorf("unmarshal roe: %w", err)
		}
	}
	e.ID = shared.ID(idStr)
	e.TenantID = shared.ID(ten)
	if projectID.Valid {
		e.ProjectID = shared.ID(projectID.String)
	}
	if businessAssetID.Valid {
		e.BusinessAssetID = shared.ID(businessAssetID.String)
	}
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
