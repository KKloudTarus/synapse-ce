package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// errRollbackProbe unwinds the transaction the whole scenario runs in. Evidence is append-only, so
// a test that commits one can never remove it: the first version of this test left a tenant, an
// engagement and an evidence row behind, and CI's second pass over the same database read them.
// Running inside one tenant transaction and returning an error leaves the database untouched.
var errRollbackProbe = errors.New("rollback probe")

// Evidence is append-only and hash-chained, enforced by a trigger that raises P0001. Deleting an
// engagement that owns any reaches that trigger, and the refusal used to arrive at the caller
// unclassified: writeError turned it into 500 "internal error" with retryable=true. It is neither
// internal nor retryable, and the console showed a Retry control that could never succeed.
//
// The trigger is correct and stays. The repository's job is to report what it means.
func TestDeleteEngagementWithSealedEvidenceIsAConflict(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	const tenant = "evidence-delete-tenant"
	const engagementID = "evidence-delete-engagement"
	repo := NewEngagementRepository(pool)

	var deleteErr error
	runErr := NewTenantTransactionRunner(pool).Run(ctx, tenant, func(txCtx context.Context) error {
		// Every statement below joins this one transaction, including the evidence store's own
		// WithTenant and the repository's WithContextTenant.
		if err := WithTenant(txCtx, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(txCtx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant); err != nil {
				return err
			}
			_, err := tx.Exec(txCtx, `INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Evidence delete')`, engagementID, tenant)
			return err
		}); err != nil {
			return err
		}
		sealed := evidence.Evidence{
			ID: shared.ID("evidence-delete-item"), EngagementID: shared.ID(engagementID),
			Kind: "admission", Content: []byte(`{}`), CreatedAt: time.Now().UTC(), CreatedBy: "operator",
		}.Seal()
		if err := NewEvidenceStore(pool).Append(txCtx, []evidence.Evidence{sealed}); err != nil {
			return err
		}
		deleteErr = repo.Delete(txCtx, shared.ID(engagementID))
		// The refusal aborts the transaction anyway; returning this makes the rollback explicit
		// and keeps the test from ever committing the evidence it just sealed.
		return errRollbackProbe
	})
	if runErr != nil && !errors.Is(runErr, errRollbackProbe) {
		t.Fatalf("scenario: %v", runErr)
	}

	if deleteErr == nil {
		t.Fatal("deleting an engagement with sealed evidence must be refused")
	}
	if !errors.Is(deleteErr, shared.ErrConflict) {
		t.Fatalf("refusal must be a conflict, so the API answers 409 and not a retryable 500; got %v", deleteErr)
	}
	if got := deleteErr.Error(); !strings.Contains(got, "append-only") && !strings.Contains(got, "sealed evidence") {
		t.Errorf("the refusal must say why: %q", got)
	}

	// Nothing the scenario wrote may survive it. CI runs this package twice against one database,
	// and a leftover evidence chain is exactly what the second pass exists to catch.
	for table, query := range map[string]string{
		"engagements": `SELECT count(*) FROM engagements WHERE id=$1`,
		"evidence":    `SELECT count(*) FROM evidence WHERE engagement_id=$1`,
	} {
		var n int
		if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, query, engagementID).Scan(&n)
		}); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s left %d row(s) behind; the second pass over this database would read them", table, n)
		}
	}
}
