package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithTenant runs fn inside a transaction whose `app.current_tenant` session variable is set to
// tenantID for the life of that transaction only. Stores of Row-Level-Security-protected tables
// (see migration 0057 and its synapse_enable_tenant_rls procedure) MUST route reads and writes
// through this helper: the policy denies every row when the variable is unset, so a query that
// runs outside WithTenant sees nothing rather than leaking across tenants. The setting is applied
// with set_config(..., is_local => true), which is transaction-scoped, so a pooled connection can
// never carry one request's tenant into the next.
//
// tenantID may be the empty string, which is the default tenant (0002_default_tenant.sql). That is
// deliberately distinct from "unset": the empty string matches the default tenant's rows, while an
// unset variable (a query that bypassed this helper) matches nothing.
func WithTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) (err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rls: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			// Rollback after a successful Commit is a no-op (ErrTxClosed); only reached on error.
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err = tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID); err != nil {
		return fmt.Errorf("rls: set tenant: %w", err)
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("rls: commit: %w", err)
	}
	return nil
}
