package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func setupScanRunTestDB(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	_, dsn := newAssessmentMigrationDB(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return ctx, pool
}

func ensureScanRunTenantAndEngagement(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, engID shared.ID) {
	t.Helper()
	tenantID = shared.TenantOrDefault(tenantID)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, tenantID.String(), "Tenant "+tenantID.String()); err != nil {
		t.Fatalf("ensure tenant: %v", err)
	}
	eng, err := engagement.New(engID, tenantID, "Eng "+engID.String(), "Client", time.Now())
	if err != nil {
		t.Fatalf("new engagement: %v", err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, eng); err != nil {
		t.Fatalf("ensure engagement: %v", err)
	}
}
