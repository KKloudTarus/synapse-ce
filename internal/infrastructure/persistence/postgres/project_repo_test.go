package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestProjectRepository(t *testing.T) {
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
	tenant := "project-test-tenant"
	_, _ = pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant) })

	r := NewProjectRepository(pool)
	p, err := project.New("project-test-id", shared.ID(tenant), "Project", "project-test", project.SourceBinding{Kind: project.SourceGit, Value: "https://example.com/repo.git", Ref: "main"}, map[string]string{"go": "default"}, "gate", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, p); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate=%v, want conflict", err)
	}
	got, err := r.GetByKey(ctx, shared.ID(tenant), p.Key)
	if err != nil || got.SourceBinding.Ref != "main" || got.DefaultProfileByLang["go"] != "default" {
		t.Fatalf("round trip: got=%+v err=%v", got, err)
	}
	if _, err := r.GetByKey(ctx, "another-tenant", p.Key); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant=%v, want not found", err)
	}
	list, err := r.List(ctx, shared.ID(tenant))
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if err := r.DeleteByKey(ctx, shared.ID(tenant), p.Key); err != nil {
		t.Fatal(err)
	}
}
