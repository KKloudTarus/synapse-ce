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

// Evidence is append-only and hash-chained, enforced by a trigger that raises P0001. Deleting an
// engagement that owns any reaches that trigger, and the refusal used to arrive at the caller
// unclassified: writeError turned it into 500 "internal error" with retryable=true. It is neither
// internal nor retryable, and the console showed a Retry control that could never succeed.
//
// The trigger is correct and must stay. The repository's job is to report what it means.
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
	tenantCtx := shared.WithTenant(ctx, tenant)
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Evidence delete')`, engagementID, tenant)
		return err
	}); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	t.Cleanup(func() {
		_ = WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
			_, _ = tx.Exec(context.Background(), `DELETE FROM engagements WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM evidence WHERE engagement_id=$1)`, engagementID)
			return nil
		})
	})

	repo := NewEngagementRepository(pool)

	// With no evidence the delete is ordinary, so the conflict below is about the evidence and
	// not about the engagement being undeletable in general.
	if err := repo.Delete(tenantCtx, shared.ID(engagementID)); err != nil {
		t.Fatalf("an engagement with no evidence must delete cleanly, got %v", err)
	}
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Evidence delete')`, engagementID, tenant)
		return err
	}); err != nil {
		t.Fatalf("reseed engagement: %v", err)
	}

	sealed := evidence.Evidence{
		ID: shared.ID("evidence-delete-item"), EngagementID: shared.ID(engagementID),
		Kind: "admission", Content: []byte(`{}`), CreatedAt: time.Now().UTC(), CreatedBy: "operator",
	}.Seal()
	if err := NewEvidenceStore(pool).Append(tenantCtx, []evidence.Evidence{sealed}); err != nil {
		t.Fatalf("append evidence: %v", err)
	}

	err = repo.Delete(tenantCtx, shared.ID(engagementID))
	if err == nil {
		t.Fatal("deleting an engagement with sealed evidence must be refused")
	}
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("refusal must be a conflict, so the API answers 409 and not a retryable 500; got %v", err)
	}
	if got := err.Error(); !strings.Contains(got, "append-only") && !strings.Contains(got, "sealed evidence") {
		t.Errorf("the refusal must say why: %q", got)
	}
}
