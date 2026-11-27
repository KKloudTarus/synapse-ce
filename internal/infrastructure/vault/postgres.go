package vault

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PostgresVault persists encrypted credentials on PostgreSQL. The column holds only the
// AES-256-GCM ciphertext (base64) – the master key lives in process memory, never in
// the DB – so a database compromise alone does not yield the secrets.
//
// Every operation runs inside the caller's tenant (withContextTenant) and names that tenant
// in its predicate, so an engagement id from another tenant resolves to nothing. A context without a
// tenant is refused, as every other tenant-scoped store refuses it. Migration 0277 gave credentials
// its tenant_id; forced row-level security on the table follows in the contract release (#1687), and
// until then this predicate is the database-side floor under rt.withEngTenant.
type PostgresVault struct {
	pool   *pgxpool.Pool
	cipher *Cipher
}

var _ ports.CredentialVault = (*PostgresVault)(nil)

// NewPostgresVault returns a Postgres-backed vault over the cipher.
func NewPostgresVault(pool *pgxpool.Pool, cipher *Cipher) *PostgresVault {
	return &PostgresVault{pool: pool, cipher: cipher}
}

func (v *PostgresVault) Put(ctx context.Context, engagementID shared.ID, name string, secret []byte) error {
	if err := validateName(name); err != nil {
		return err
	}
	ct, err := v.cipher.Seal(secret, aad(engagementID, name))
	if err != nil {
		return err
	}
	return withContextTenant(ctx, v.pool, func(tx pgx.Tx) error {
		tenantID, _ := shared.TenantFrom(ctx)
		// The insert trigger refuses a tenant that does not own the engagement, so the upsert cannot
		// overwrite another tenant's secret that shares this (engagement_id, name).
		tag, err := tx.Exec(ctx,
			`INSERT INTO credentials (tenant_id, engagement_id, name, ciphertext, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, now(), now())
			 ON CONFLICT (engagement_id, name) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = now()
			 WHERE credentials.tenant_id = EXCLUDED.tenant_id`,
			tenantID.String(), engagementID.String(), name, ct)
		if err != nil {
			return fmt.Errorf("put credential: %w", err)
		}
		// The conditional update writes nothing when the stored row belongs to no tenant or another one.
		// Reporting success then would let the caller audit a rotation that never happened.
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("credential %q: %w: the stored row is not this tenant's", name, shared.ErrConflict)
		}
		return nil
	})
}

func (v *PostgresVault) Resolve(ctx context.Context, engagementID shared.ID, name string) ([]byte, error) {
	var ct string
	err := withContextTenant(ctx, v.pool, func(tx pgx.Tx) error {
		tenantID, _ := shared.TenantFrom(ctx)
		return tx.QueryRow(ctx,
			`SELECT ciphertext FROM credentials WHERE tenant_id=$1 AND engagement_id=$2 AND name=$3`,
			tenantID.String(), engagementID.String(), name).Scan(&ct)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("credential %q: %w", name, shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve credential: %w", err)
	}
	return v.cipher.Open(ct, aad(engagementID, name))
}

func (v *PostgresVault) List(ctx context.Context, engagementID shared.ID) (out []ports.CredentialMeta, err error) {
	err = withContextTenant(ctx, v.pool, func(tx pgx.Tx) error {
		tenantID, _ := shared.TenantFrom(ctx)
		rows, err := tx.Query(ctx,
			`SELECT name, created_at, updated_at FROM credentials WHERE tenant_id=$1 AND engagement_id=$2 ORDER BY name`,
			tenantID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list credentials: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var m ports.CredentialMeta
			if err := rows.Scan(&m.Name, &m.CreatedAt, &m.UpdatedAt); err != nil {
				return fmt.Errorf("scan credential: %w", err)
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

func (v *PostgresVault) Delete(ctx context.Context, engagementID shared.ID, name string) error {
	return withContextTenant(ctx, v.pool, func(tx pgx.Tx) error {
		tenantID, _ := shared.TenantFrom(ctx)
		tag, err := tx.Exec(ctx,
			`DELETE FROM credentials WHERE tenant_id=$1 AND engagement_id=$2 AND name=$3`, tenantID.String(), engagementID.String(), name)
		if err != nil {
			return fmt.Errorf("delete credential: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("credential %q: %w", name, shared.ErrNotFound)
		}
		return nil
	})
}

// withContextTenant runs fn in a transaction bound to the context's tenant, the way
// postgres.WithContextTenant does for every other store. It is local because the postgres package
// imports this one. A context without a tenant is refused rather than read unscoped.
func withContextTenant(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) (err error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("vault: begin: %w", err)
	}
	committed := false
	defer func() {
		// Rolled back on every path that did not commit, a panic in fn included, and on a context of its
		// own: the caller's may already be cancelled, which would leave the connection holding the tx.
		if !committed {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = tx.Rollback(rollbackCtx)
			cancel()
		}
	}()
	if _, err = tx.Exec(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID.String()); err != nil {
		return fmt.Errorf("vault: bind tenant: %w", err)
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("vault: commit: %w", err)
	}
	committed = true
	return nil
}
