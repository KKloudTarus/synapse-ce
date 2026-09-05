package postgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestFindingProjectionClaimPostgresAtomicAndRLS(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	id := randHex(t)
	tenant, otherTenant := shared.ID("projection-a-"+id), shared.ID("projection-b-"+id)
	engagementID, judgmentID := shared.ID("projection-eng-"+id), shared.ID("projection-judgment-"+id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1), ($2, $2)`, tenant.String(), otherTenant.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id IN ($1, $2)`, tenant.String(), otherTenant.String())
	})
	eng, err := engagement.New(engagementID, tenant, "projection", "client", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, eng); err != nil {
		t.Fatalf("create engagement: %v", err)
	}

	repo := NewFindingRepository(pool)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, mode := range []ports.FindingProjectionMode{ports.FindingProjectionSAST, ports.FindingProjectionDAST} {
		wg.Add(1)
		go func(mode ports.FindingProjectionMode) {
			defer wg.Done()
			<-start
			errs <- repo.ClaimFindingProjection(context.Background(), tenant, engagementID, judgmentID, mode)
		}(mode)
	}
	close(start)
	wg.Wait()
	close(errs)

	var succeeded, conflicted int
	for err := range errs {
		if err == nil {
			succeeded++
		} else if errors.Is(err, shared.ErrConflict) {
			conflicted++
		} else {
			t.Fatalf("claim: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("claims: %d succeeded, %d conflicted; want 1 each", succeeded, conflicted)
	}

	var mode string
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT mode FROM finding_projection_claims WHERE tenant_id=$1 AND engagement_id=$2 AND judgment_id=$3`, tenant.String(), engagementID.String(), judgmentID.String()).Scan(&mode)
	}); err != nil {
		t.Fatalf("read claim: %v", err)
	}
	if err := repo.ClaimFindingProjection(ctx, tenant, engagementID, judgmentID, ports.FindingProjectionMode(mode)); err != nil {
		t.Fatalf("same-mode retry: %v", err)
	}
	// ErrNotFound, not ErrConflict, and that is the DESIRABLE answer rather than a near miss. The insert
	// is guarded by WHERE EXISTS (SELECT 1 FROM engagements ...) under the other tenant's RLS scope, so
	// the engagement is simply not visible. Reporting a conflict would confirm that this engagement
	// exists in some other tenant, which is a disclosure a tenant-isolation boundary should not make.
	if err := repo.ClaimFindingProjection(ctx, otherTenant, engagementID, "other-"+judgmentID, ports.FindingProjectionSAST); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a cross-tenant claim must fail closed as not-found (no existence disclosure), got %v", err)
	}
	if err := repo.ClaimFindingProjection(ctx, otherTenant, engagementID, "other-"+judgmentID, ports.FindingProjectionSAST); errors.Is(err, shared.ErrConflict) {
		t.Fatal("a cross-tenant claim must not report a conflict: that discloses the engagement exists elsewhere")
	}

	role := uniqueProbeRole(t, "projection_claim_role")
	_, _ = pool.Exec(ctx, `DROP OWNED BY `+role)
	_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON finding_projection_claims TO ` + role,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	if err := WithTenant(ctx, pool, "", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
			return err
		}
		var visible int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM finding_projection_claims WHERE tenant_id=$1`, tenant.String()).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			t.Fatalf("no-tenant RLS query saw %d claims", visible)
		}
		return nil
	}); err != nil {
		t.Fatalf("no-tenant RLS query: %v", err)
	}
}
