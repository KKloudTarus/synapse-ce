package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

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
