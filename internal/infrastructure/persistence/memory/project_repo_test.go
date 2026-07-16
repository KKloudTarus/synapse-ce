package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestProjectRepositoryZeroTenantSelectionIsDeterministic(t *testing.T) {
	ctx := context.Background()
	r := NewProjectRepository()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	for _, p := range []*project.Project{
		mustProject(t, "p2", "tenant-b", now),
		mustProject(t, "p1", "tenant-a", now),
	} {
		if err := r.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	got, err := r.GetByKey(ctx, "", "project")
	if err != nil || got.ID != "p1" {
		t.Fatalf("zero-tenant get = %+v, %v; want p1", got, err)
	}
	if err := r.DeleteByKey(ctx, "", "project"); err != nil {
		t.Fatal(err)
	}
	got, err = r.GetByKey(ctx, "", "project")
	if err != nil || got.ID != "p2" {
		t.Fatalf("zero-tenant get after delete = %+v, %v; want p2", got, err)
	}
}

func mustProject(t *testing.T, id, tenant string, now time.Time) *project.Project {
	t.Helper()
	p, err := project.New(shared.ID(id), shared.ID(tenant), "Project", "project", project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}, nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProjectRepository(t *testing.T) {
	ctx := context.Background()
	r := NewProjectRepository()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	p, err := project.New("p1", "tenant-a", "Project", "project", project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}, map[string]string{"go": "default"}, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, p); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate = %v, want conflict", err)
	}
	p.Name = "mutated"
	got, err := r.GetByKey(ctx, "tenant-a", "project")
	if err != nil || got.Name != "Project" {
		t.Fatalf("copy-on-write failed: got=%+v err=%v", got, err)
	}
	got.DefaultProfileByLang["go"] = "mutated"
	got, _ = r.GetByKey(ctx, "tenant-a", "project")
	if got.DefaultProfileByLang["go"] != "default" {
		t.Fatal("copy-on-read failed")
	}
	if _, err := r.GetByKey(ctx, "tenant-b", "project"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read = %v, want not found", err)
	}
	list, err := r.List(ctx, "tenant-a")
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if err := r.DeleteByKey(ctx, "tenant-a", "project"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetByKey(ctx, "tenant-a", "project"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("after delete = %v, want not found", err)
	}
}
