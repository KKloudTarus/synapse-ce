package postgres

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// setupScanRunTestDB creates a database per test. Scan-run tests intentionally
// seal provenance, and migrations correctly refuse to roll such data back; a
// shared database would therefore leak sealed rows into unrelated migration
// tests running in parallel under go test ./....
func setupScanRunTestDB(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	dsn := isolatedScanRunTestDSN(t)
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

func isolatedScanRunTestDSN(t *testing.T) string {
	t.Helper()
	sharedDSN := testDSN(t)
	parsed, err := url.Parse(sharedDSN)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatalf("parse PostgreSQL test DSN: %v", err)
	}

	databaseName := "synapse_scanrun_" + randHex(t)[:12]
	databaseIdent := pgx.Identifier{databaseName}.Sanitize()
	ctx := context.Background()
	admin, err := Connect(ctx, sharedDSN)
	if err != nil {
		t.Fatalf("connect scan-run database admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseIdent); err != nil {
		admin.Close()
		t.Fatalf("create isolated scan-run database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, databaseName)
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+databaseIdent); err != nil {
			t.Errorf("drop isolated scan-run database: %v", err)
		}
		admin.Close()
	})

	isolated := *parsed
	isolated.Path = fmt.Sprintf("/%s", databaseName)
	isolated.RawPath = ""
	return isolated.String()
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
