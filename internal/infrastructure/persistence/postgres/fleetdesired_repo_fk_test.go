package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFleetDesiredRepositoryMapsMissingSubjectToConflict(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	const tenant = "fd-missing-subject"
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, tenant, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant)
	})

	now := time.Now().UTC().Truncate(time.Second)
	err = NewFleetDesiredRepository(pool).Put(ctx, &fleetdesired.State{
		TenantID: tenant, AssetID: "asset-that-disappeared", PolicyID: "policy-missing-subject",
		Capabilities: []string{"process"}, UpdatedBy: "operator", Version: 1,
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	})
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("missing desired-state subject error=%v, want ErrConflict", err)
	}
}
