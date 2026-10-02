package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const userCols = `id, name, role, api_key_hash, disabled, created_at, updated_at, tenant_id`

// userTenantPredicate scopes a query to one tenant WITHOUT relying on row level security being
// present on the users table. It normalizes the stored tenant the same way shared.TenantOrDefault
// does in Go, so the bootstrap admin's empty tenant_id and an explicit 'default' name one tenant.
// $1 is the default-tenant literal; $2 is the caller's already-normalized tenant.
const userTenantPredicate = `COALESCE(NULLIF(tenant_id, ''), $1) = $2`

// UserRepository persists operator identities to PostgreSQL.
type UserRepository struct{ pool *pgxpool.Pool }

// NewUserRepository returns a repository backed by the given pool.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository { return &UserRepository{pool: pool} }

var _ ports.UserRepository = (*UserRepository)(nil)

// Create inserts a user inside its own tenant transaction, joining the one TenantTransactionRunner
// bound to ctx when present, so the users row, its audit record and the derived identity
// projection commit or roll back together.
func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	tenantID := shared.TenantOrDefault(shared.ID(u.TenantID))
	return withUserTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (`+userCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			u.ID.String(), u.Name, string(u.Role), u.APIKeyHash, u.Disabled, u.Audit.CreatedAt, u.Audit.UpdatedAt, u.TenantID); err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		if err := projectLegacyUser(ctx, tx, tenantID, legacyUserState{}, u, u.Audit.UpdatedAt); err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		return nil
	})
}

// withUserTenant runs fn bound to the user's own tenant. A platform administrator provisions into
// another tenant from inside its own tenant transaction; that transaction is rebound to the
// target tenant for fn and restored afterwards, so the users row, its projection and the caller's
// audit record still share one commit. Every other caller gets ordinary WithTenant semantics.
func withUserTenant(ctx context.Context, pool *pgxpool.Pool, tenantID shared.ID, fn func(pgx.Tx) error) error {
	bound, ok := ctx.Value(tenantTransactionKey{}).(tenantTransaction)
	if !ok || bound.tenantID == tenantID.String() {
		return WithTenant(ctx, pool, tenantID.String(), fn)
	}
	if _, err := bound.tx.Exec(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID.String()); err != nil {
		return fmt.Errorf("rls: rebind tenant: %w", err)
	}
	fnErr := fn(bound.tx)
	if _, err := bound.tx.Exec(ctx, `SELECT set_config('app.current_tenant', $1, true)`, bound.tenantID); err != nil {
		return errors.Join(fnErr, fmt.Errorf("rls: restore tenant: %w", err))
	}
	return normalizePersistenceError(fnErr)
}

// Upsert inserts or refreshes a user by id inside the user's tenant transaction and projects it.
// The bootstrap operator is never projected.
func (r *UserRepository) Upsert(ctx context.Context, u *user.User) error {
	tenantID := shared.TenantOrDefault(shared.ID(u.TenantID))
	return withUserTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		before, err := lockLegacyUserState(ctx, tx, tenantID, u.ID)
		if err != nil {
			return fmt.Errorf("upsert user: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (`+userCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			 ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, role=EXCLUDED.role,
			     api_key_hash=EXCLUDED.api_key_hash, disabled=EXCLUDED.disabled, updated_at=EXCLUDED.updated_at,
			     tenant_id=EXCLUDED.tenant_id`,
			u.ID.String(), u.Name, string(u.Role), u.APIKeyHash, u.Disabled, u.Audit.CreatedAt, u.Audit.UpdatedAt, u.TenantID); err != nil {
			return fmt.Errorf("upsert user: %w", err)
		}
		if err := projectLegacyUser(ctx, tx, tenantID, before, u, u.Audit.UpdatedAt); err != nil {
			return fmt.Errorf("upsert user: %w", err)
		}
		return nil
	})
}

// Bootstrap atomically seeds or refreshes the bootstrap administrator. The audit row
// is appended in the same transaction only when the user is first inserted, so
// concurrent API startups cannot create duplicate bootstrap audit events.
func (r *UserRepository) Bootstrap(ctx context.Context, u *user.User, auditEntry ports.AuditEntry) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap user: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var inserted bool
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (`+userCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (id) DO NOTHING
		 RETURNING true`,
		u.ID.String(), u.Name, string(u.Role), u.APIKeyHash, u.Disabled, u.Audit.CreatedAt, u.Audit.UpdatedAt, u.TenantID).Scan(&inserted); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("bootstrap user: insert: %w", err)
	}
	if !inserted {
		if _, err := tx.Exec(ctx,
			`UPDATE users SET name=$2, role=$3, api_key_hash=$4, disabled=$5, updated_at=$6, tenant_id=$7 WHERE id=$1`,
			u.ID.String(), u.Name, string(u.Role), u.APIKeyHash, u.Disabled, u.Audit.UpdatedAt, u.TenantID); err != nil {
			return fmt.Errorf("bootstrap user: refresh: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", shared.DefaultTenant.String()); err != nil {
			return fmt.Errorf("bootstrap user: set audit tenant: %w", err)
		}
		if err := appendTenantAudit(ctx, tx, shared.DefaultTenant.String(), auditEntry); err != nil {
			return fmt.Errorf("bootstrap user: audit: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("bootstrap user: commit: %w", err)
	}
	return nil
}

func (r *UserRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*user.User, error) {
	u, err := scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE `+userTenantPredicate+` AND id=$3`,
		shared.DefaultTenant.String(), shared.TenantOrDefault(tenantID).String(), id.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		// A user in another tenant is not found, never forbidden: existence is not revealed.
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

// Update writes the mutable fields of a user that already exists in tenantID. tenant_id is absent
// from the SET list, so an update can never move a user between tenants, and the tenant predicate
// means a cross-tenant id updates nothing.
func (r *UserRepository) Update(ctx context.Context, tenantID shared.ID, u *user.User) error {
	tenant := shared.TenantOrDefault(tenantID)
	return WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		// Lock the prior row so projection sees exactly the transition this write makes.
		before, err := lockLegacyUserState(ctx, tx, tenant, u.ID)
		if err != nil {
			return fmt.Errorf("update user: %w", err)
		}
		if !before.exists {
			return shared.ErrNotFound
		}
		tag, err := tx.Exec(ctx,
			`UPDATE users SET name=$4, role=$5, api_key_hash=$6, disabled=$7, updated_at=$8
			 WHERE `+userTenantPredicate+` AND id=$3`,
			shared.DefaultTenant.String(), shared.TenantOrDefault(tenantID).String(), u.ID.String(),
			u.Name, string(u.Role), u.APIKeyHash, u.Disabled, u.Audit.UpdatedAt)
		if err != nil {
			return fmt.Errorf("update user: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		// Same transaction as the users write: the derived credential and the exact-digest index
		// follow a rotation or disable atomically, and a projection failure rolls the write back.
		if err := projectLegacyUser(ctx, tx, tenant, before, u, u.Audit.UpdatedAt); err != nil {
			return fmt.Errorf("update user: %w", err)
		}
		return nil
	})
}

// GetByAPIKeyHash is the authentication path: the tenant is unknown until the presented token
// resolves to a user, so this is the one user lookup without a tenant predicate. The key is the
// SHA-256 digest of a 192-bit random secret, and the resolved user's own tenant scopes every
// subsequent read and write.
func (r *UserRepository) GetByAPIKeyHash(ctx context.Context, hash string) (*user.User, error) {
	u, err := scanUser(r.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE api_key_hash=$1`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by key: %w", err)
	}
	return u, nil
}

func (r *UserRepository) List(ctx context.Context, tenantID shared.ID) ([]*user.User, error) {
	return r.list(ctx, tenantID, "")
}

// ListForUpdate locks and drains the tenant's rows in canonical ID order before reading them in
// ordinary created_at/id presentation order. Backfill takes the same lock order, so roster-wide
// mutations cannot deadlock with a batch whose IDs sort differently from its creation timestamps.
// Outside a transaction the locks are released immediately and this is just List.
func (r *UserRepository) ListForUpdate(ctx context.Context, tenantID shared.ID) ([]*user.User, error) {
	var out []*user.User
	tenant := shared.TenantOrDefault(tenantID).String()
	err := WithTenant(ctx, r.pool, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM users WHERE `+userTenantPredicate+` ORDER BY id FOR UPDATE`, shared.DefaultTenant.String(), tenant)
		if err != nil {
			return fmt.Errorf("lock users: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("scan locked user: %w", err)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("lock users: %w", err)
		}
		out, err = listUsers(ctx, tx, tenant)
		return err
	})
	return out, err
}

var _ ports.UserRosterLocker = (*UserRepository)(nil)

func (r *UserRepository) list(ctx context.Context, tenantID shared.ID, _ string) ([]*user.User, error) {
	var out []*user.User
	tenant := shared.TenantOrDefault(tenantID).String()
	err := WithTenant(ctx, r.pool, tenant, func(tx pgx.Tx) error {
		var err error
		out, err = listUsers(ctx, tx, tenant)
		return err
	})
	return out, err
}

func listUsers(ctx context.Context, tx pgx.Tx, tenant string) ([]*user.User, error) {
	rows, err := tx.Query(ctx, `SELECT `+userCols+` FROM users WHERE `+userTenantPredicate+` ORDER BY created_at ASC, id ASC`, shared.DefaultTenant.String(), tenant)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	out := []*user.User{}
	for rows.Next() {
		u, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan user: %w", scanErr)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return out, nil
}

func scanUser(row rowScanner) (*user.User, error) {
	var (
		u        user.User
		id, role string
	)
	if err := row.Scan(&id, &u.Name, &role, &u.APIKeyHash, &u.Disabled, &u.Audit.CreatedAt, &u.Audit.UpdatedAt, &u.TenantID); err != nil {
		return nil, err
	}
	u.ID = shared.ID(id)
	u.Role = user.Role(role)
	return &u, nil
}
