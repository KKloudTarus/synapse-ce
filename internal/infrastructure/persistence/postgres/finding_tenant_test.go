package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFindingRepositoryDerivesEngagementTenant(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	id := randHex(t)
	projectedTenant := shared.ID("finding-tenant-" + id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, projectedTenant.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, projectedTenant.String())
	})
	for _, tc := range []struct {
		name, tenant string
	}{
		{name: "projected", tenant: projectedTenant.String()},
		{name: "default", tenant: "default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engagementID := shared.ID(tc.name + "-engagement-" + id)
			engagementTenant := shared.ID("")
			if tc.tenant != "default" {
				engagementTenant = projectedTenant
			}
			eng, err := engagement.New(engagementID, engagementTenant, tc.name, "client", time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if err := NewEngagementRepository(pool).Create(ctx, eng); err != nil {
				t.Fatal(err)
			}
			f := finding.Finding{ID: shared.ID(tc.name + "-finding-" + id), EngagementID: engagementID, Title: "finding", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: tc.name + "-dedup-" + id, Audit: shared.Audit{CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}}
			if err := NewFindingRepository(pool).Upsert(ctx, []finding.Finding{f}); err != nil {
				t.Fatal(err)
			}
			var tenant string
			if err := pool.QueryRow(ctx, `SELECT tenant_id FROM findings WHERE id=$1`, f.ID.String()).Scan(&tenant); err != nil {
				t.Fatal(err)
			}
			if tenant != tc.tenant {
				t.Fatalf("finding tenant = %q, want %q", tenant, tc.tenant)
			}
		})
	}
}
