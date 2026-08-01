package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// WithTenantTx runs fn in a transaction whose RLS tenant context cannot escape
// to another pooled request. The empty ID is the existing default tenant; an
// absent setting is intentionally impossible through this API.
func WithTenantTx(ctx context.Context, pool *pgxpool.Pool, tenantID shared.ID, fn func(pgx.Tx) error) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	return nil
}

// WithContextTenantTx is for ports whose historic signature does not carry a
// tenant ID. HTTP authentication and durable jobs must bind the context first;
// missing context fails closed rather than becoming a cross-tenant wildcard.
func WithContextTenantTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("tenant context is required")
	}
	return WithTenantTx(ctx, pool, tenantID, fn)
}
