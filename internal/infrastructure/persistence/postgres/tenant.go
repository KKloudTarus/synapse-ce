package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type tenantTransactionKey struct{}

type tenantTransaction struct {
	tenantID string
	tx       pgx.Tx
}

type TenantTransactionRunner struct{ pool *pgxpool.Pool }

func NewTenantTransactionRunner(pool *pgxpool.Pool) *TenantTransactionRunner {
	return &TenantTransactionRunner{pool: pool}
}

var _ ports.TenantTransactionRunner = (*TenantTransactionRunner)(nil)

func (runner *TenantTransactionRunner) Run(ctx context.Context, tenantID shared.ID, fn func(context.Context) error) error {
	if tenantID.IsZero() || fn == nil {
		return fmt.Errorf("%w: tenant transaction identity is required", shared.ErrValidation)
	}
	return WithTenant(ctx, runner.pool, tenantID.String(), func(tx pgx.Tx) error {
		txCtx := shared.WithTenant(context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{tenantID: tenantID.String(), tx: tx}), tenantID)
		return fn(txCtx)
	})
}

// WithTenant runs fn inside a transaction whose `app.current_tenant` session variable is set to
// tenantID for the life of that transaction only. Stores of Row-Level-Security-protected tables
// (see migration 0057 and its synapse_enable_tenant_rls procedure) MUST route reads and writes
// through this helper: the policy denies every row when the tenant resolves to NULL, so a query
// that runs outside WithTenant sees nothing rather than leaking across tenants. The setting is
// applied with set_config(..., is_local => true), which is transaction-scoped.
//
// Fail-closed semantics: an empty tenantID resolves (via synapse_current_tenant's NULLIF) to NULL
// and therefore matches no row. Under RLS the empty string is DENY, not the default tenant, so
// callers of RLS-protected tables must pass a non-empty tenant id. This closes the placeholder-GUC
// reset hazard: app.current_tenant reverts to the empty string (not "unset") after a transaction,
// and mapping the empty string to NULL means a connection reused outside WithTenant still denies
// rather than exposing default-tenant rows.
func WithTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) (err error) {
	if bound, ok := ctx.Value(tenantTransactionKey{}).(tenantTransaction); ok {
		if bound.tenantID != tenantID {
			return fmt.Errorf("%w: nested tenant transaction mismatch", shared.ErrValidation)
		}
		return normalizePersistenceError(fn(bound.tx))
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rls: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		// Roll back on any non-committed exit (error OR a panic in fn) with a fresh, bounded
		// context so an already-canceled request context cannot skip releasing the connection.
		// Keying on a committed flag rather than on err also rolls back when fn panics, which
		// would otherwise leak the connection back to the pool with an open transaction.
		rbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rbCtx)
	}()
	if _, err = tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID); err != nil {
		return fmt.Errorf("rls: set tenant: %w", err)
	}
	if err = fn(tx); err != nil {
		return normalizePersistenceError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("rls: commit: %w: %w", ErrTenantCommit, err)
	}
	committed = true
	return nil
}

// ErrTenantCommit marks a failure of the COMMIT that ends a WithTenant transaction, as opposed to
// a failure inside fn. Once COMMIT has been sent its durable outcome can be unknowable, so a
// caller that compensates on failure (by deleting an artifact it wrote outside the database, say)
// must not treat this as "the transaction did not happen".
var ErrTenantCommit = errors.New("tenant transaction commit failed")

// normalizePersistenceError translates database-enforced application conflicts into the same
// domain sentinel used by deterministic pre-checks. The telemetry asset-binding constraint is a
// race backstop, so callers must observe a conflict (HTTP 409 at the edge), not a generic 500.
func normalizePersistenceError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "uq_telemetry_asset_bindings_asset" {
		return fmt.Errorf("%w: telemetry asset is already bound to another agent", shared.ErrConflict)
	}
	return err
}

// WithContextTenant runs fn under the immutable tenant previously bound to ctx.
func WithContextTenant(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return WithTenant(ctx, pool, tenantID.String(), fn)
}

// contextTenantTx returns the transaction already bound by TenantTransactionRunner.
// It permits consumer-level composite operations to reuse the same tenant-local
// transaction across concrete repositories without exposing pgx through ports.
func contextTenantTx(ctx context.Context, tenantID shared.ID) (pgx.Tx, bool, error) {
	bound, ok := ctx.Value(tenantTransactionKey{}).(tenantTransaction)
	if !ok {
		return nil, false, nil
	}
	if bound.tenantID != tenantID.String() {
		return nil, true, fmt.Errorf("%w: nested tenant transaction mismatch", shared.ErrValidation)
	}
	return bound.tx, true, nil
}

// CheckRLSRuntimeRole reports whether the role the pool connects as can actually be constrained by
// Row Level Security. RLS is bypassed entirely by SUPERUSER and BYPASSRLS roles regardless of
// FORCE ROW LEVEL SECURITY, so if the runtime role holds either attribute the whole tenant
// isolation guarantee is silently a no-op. It returns a non-nil error naming the offending
// attribute when the role would bypass RLS.
//
// This is intended to gate multi-tenant enablement (fail-closed): the caller that turns on
// RLS-protected tables must refuse to serve if this returns an error. It is exported and separate
// so that path can enforce it at startup, while single-tenant deployments that connect as a
// superuser and use no RLS-protected table are not forced to change their role.
func CheckRLSRuntimeRole(ctx context.Context, pool *pgxpool.Pool) error {
	var super, bypass, databaseCreate, schemaCreate, ownsRLSTable bool
	err := pool.QueryRow(ctx, `SELECT r.rolsuper, r.rolbypassrls,
		has_database_privilege(current_user, current_database(), 'CREATE'),
		has_schema_privilege(current_user, 'public', 'CREATE'),
		EXISTS (SELECT 1 FROM pg_class c WHERE c.relkind IN ('r','p') AND c.relrowsecurity AND c.relowner = r.oid)
		FROM pg_roles r WHERE r.rolname = current_user`).Scan(&super, &bypass, &databaseCreate, &schemaCreate, &ownsRLSTable)
	if err != nil {
		return fmt.Errorf("rls: inspect runtime role: %w", err)
	}
	switch {
	case super:
		return fmt.Errorf("rls: runtime DB role %w: role is SUPERUSER, which bypasses row level security", errRLSRoleBypasses)
	case bypass:
		return fmt.Errorf("rls: runtime DB role %w: role has BYPASSRLS, which bypasses row level security", errRLSRoleBypasses)
	case ownsRLSTable:
		return fmt.Errorf("rls: runtime DB role %w: role owns an RLS table", errRLSRoleBypasses)
	case schemaCreate || databaseCreate:
		return fmt.Errorf("rls: runtime DB role %w: role has schema or database DDL authority", errRLSRoleBypasses)
	default:
		return nil
	}
}

// errRLSRoleBypasses is the sentinel wrapped by CheckRLSRuntimeRole so callers can match it.
var errRLSRoleBypasses = fmt.Errorf("cannot enforce isolation")

// requireTenant runs fn inside a WithTenant transaction bound to tenantID, refusing an empty
// tenant up front. WithTenant would otherwise bind the empty string and let synapse_current_tenant() resolve it
// to the RLS DENY sentinel, so the caller would see an empty result set or a not-found instead of
// the programming error that produced it. Repositories of RLS-protected tables whose port carries
// an explicit tenant argument use this; those whose port relies on the ambient tenant use
// WithContextTenant.
func requireTenant(ctx context.Context, pool *pgxpool.Pool, tenantID shared.ID, fn func(pgx.Tx) error) error {
	if tenantID.IsZero() {
		return fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	return WithTenant(ctx, pool, tenantID.String(), fn)
}

// listTenantIDs enumerates every tenant so a cross-tenant maintenance sweep can run one
// tenant-bound query per tenant instead of one unscoped query over an RLS-protected table.
// tenants is deliberate global reference data and carries no policy of its own; label names the
// sweep for the wrapped error. This is the same fan-out the job queue's Claim and the engagement
// repository's reconciliation scan already use.
func listTenantIDs(ctx context.Context, pool *pgxpool.Pool, label string) ([]shared.ID, error) {
	rows, err := pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list tenants for %s: %w", label, err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var tenantID shared.ID
		if err := rows.Scan(&tenantID); err != nil {
			return nil, fmt.Errorf("scan tenant for %s: %w", label, err)
		}
		// The legacy empty tenant is the RLS DENY sentinel, never a partition to sweep.
		if tenantID.IsZero() {
			continue
		}
		out = append(out, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tenants for %s: %w", label, err)
	}
	return out, nil
}
