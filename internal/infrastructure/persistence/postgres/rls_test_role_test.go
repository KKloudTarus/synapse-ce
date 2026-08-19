package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const fleetDesiredRLSTestRole = "synapse_fd_rls_test"

// fleetDesiredRLSRole returns a transaction hook that switches to a real non-superuser,
// non-BYPASSRLS role when the integration DSN itself bypasses RLS (as the standard CI postgres admin
// user does). If the DSN already uses a normal role the hook is a no-op. This makes policy tests prove
// RLS behavior rather than merely exercise WHERE predicates under a privileged session.
func fleetDesiredRLSRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool) func(context.Context, pgx.Tx) error {
	t.Helper()
	var superuser, bypass bool
	if err := pool.QueryRow(ctx, `
		SELECT rolsuper, rolbypassrls
		FROM pg_roles
		WHERE rolname = current_user
	`).Scan(&superuser, &bypass); err != nil {
		t.Fatalf("inspect postgres test role: %v", err)
	}
	if !superuser && !bypass {
		return func(context.Context, pgx.Tx) error { return nil }
	}
	if !superuser {
		// A BYPASSRLS non-superuser cannot reliably create the isolated role needed to test itself.
		// Treat that DSN as an invalid integration-test configuration rather than claiming RLS passed.
		t.Fatalf("postgres integration role has BYPASSRLS without superuser; cannot prove tenant RLS safely")
	}

	cleanup := func(cleanCtx context.Context) {
		_, _ = pool.Exec(cleanCtx, `DROP OWNED BY `+fleetDesiredRLSTestRole)
		_, _ = pool.Exec(cleanCtx, `DROP ROLE IF EXISTS `+fleetDesiredRLSTestRole)
	}
	cleanup(ctx)
	if _, err := pool.Exec(ctx, `CREATE ROLE `+fleetDesiredRLSTestRole+` NOLOGIN NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create non-bypass RLS test role: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+fleetDesiredRLSTestRole); err != nil {
		cleanup(ctx)
		t.Fatalf("grant schema usage to RLS test role: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT SELECT, UPDATE ON fleet_desired_state TO `+fleetDesiredRLSTestRole); err != nil {
		cleanup(ctx)
		t.Fatalf("grant desired-state access to RLS test role: %v", err)
	}
	t.Cleanup(func() { cleanup(context.Background()) })

	return func(execCtx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(execCtx, `SET LOCAL ROLE `+fleetDesiredRLSTestRole); err != nil {
			return fmt.Errorf("activate non-bypass RLS test role: %w", err)
		}
		return nil
	}
}
