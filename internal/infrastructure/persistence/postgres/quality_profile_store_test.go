package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestQualityProfileStoreIntegration(t *testing.T) {
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
	t.Cleanup(pool.Close)

	tenant := shared.ID("profile-test-tenant")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM quality_profiles WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant)
	})

	store := NewQualityProfileStore(pool)
	p := qualityprofile.Profile{
		Key: "team-go", Name: "Team Go", Language: "Go", Parent: "synapse-way-go",
		ActivatedRules: map[string]qualityprofile.RuleActivation{
			"go-a": {Severity: shared.SeverityCritical},
			"go-b": {},
		},
	}
	if err := store.Create(ctx, tenant, p); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, tenant, p); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate create must conflict, got %v", err)
	}
	got, err := store.Get(ctx, tenant, "team-go")
	if err != nil || got.Language != "Go" || got.Parent != "synapse-way-go" || got.ActivatedRules["go-a"].Severity != shared.SeverityCritical || len(got.ActivatedRules) != 2 {
		t.Fatalf("get = %+v err=%v", got, err)
	}
	// Cross-tenant read is isolated.
	if _, err := store.Get(ctx, "other-tenant", "team-go"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get = %v, want not found", err)
	}
	// Update: deactivate go-a.
	delete(got.ActivatedRules, "go-a")
	if err := store.Update(ctx, tenant, got); err != nil {
		t.Fatal(err)
	}
	reread, _ := store.Get(ctx, tenant, "team-go")
	if _, ok := reread.ActivatedRules["go-a"]; ok || len(reread.ActivatedRules) != 1 {
		t.Fatalf("update did not persist: %+v", reread.ActivatedRules)
	}
	list, err := store.List(ctx, tenant)
	if err != nil || len(list) != 1 || list[0].Key != "team-go" {
		t.Fatalf("list = %+v err=%v", list, err)
	}
	if err := store.Delete(ctx, tenant, "team-go"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, tenant, "team-go"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted profile must be gone, got %v", err)
	}
}
