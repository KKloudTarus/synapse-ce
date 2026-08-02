package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAssessmentRepositoryCreatesHierarchyAtomically(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("assessment-%d", time.Now().UnixNano())
	tenant := shared.ID(suffix + "-tenant")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO appsec_business_services (id,tenant_id,name,description,criticality,lifecycle,created_at,updated_at) VALUES ($1,$2,'Assessment service','','high','active',now(),now())`, suffix+"-service", tenant); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a, err := assessment.New(shared.ID(suffix+"-assessment"), tenant, shared.ID(suffix+"-service"), "Release", "", assessment.Policy{}, now)
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagement.New(shared.ID(suffix+"-engagement"), tenant, "Release execution", "", now)
	if err != nil {
		t.Fatal(err)
	}
	e.AssessmentID = a.ID
	repo := NewAssessmentRepository(pool)
	if err := repo.Create(shared.WithTenant(ctx, tenant), a, []*engagement.Engagement{e}); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(shared.WithTenant(ctx, tenant), a.ID)
	if err != nil || got.ID != a.ID {
		t.Fatalf("get=%+v err=%v", got, err)
	}
}
