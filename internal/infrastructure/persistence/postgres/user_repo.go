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

// UserRepository persists operator identities to PostgreSQL.
type UserRepository struct{ pool *pgxpool.Pool }

// NewUserRepository returns a repository backed by the given pool.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository { return &UserRepository{pool: pool} }

var _ ports.UserRepository = (*UserRepository)(nil)

func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO users (`+userCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		u.ID.String(), u.Name, string(u.Role), u.APIKeyHash, u.Disabled, u.Audit.CreatedAt, u.Audit.UpdatedAt, u.TenantID); err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (r *UserRepository) Upsert(ctx context.Context, u *user.User) error {
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO users (`+userCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, role=EXCLUDED.role,
		     api_key_hash=EXCLUDED.api_key_hash, disabled=EXCLUDED.disabled, updated_at=EXCLUDED.updated_at,
		     tenant_id=EXCLUDED.tenant_id`,
		u.ID.String(), u.Name, string(u.Role), u.APIKeyHash, u.Disabled, u.Audit.CreatedAt, u.Audit.UpdatedAt, u.TenantID); err != nil {
		return fmt.Errorf("upsert user: %w", err)
	}
	return nil
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

func (r *UserRepository) GetByID(ctx context.Context, id shared.ID) (*user.User, error) {
	u, err := scanUser(r.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

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

func (r *UserRepository) List(ctx context.Context) ([]*user.User, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	out := []*user.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
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
