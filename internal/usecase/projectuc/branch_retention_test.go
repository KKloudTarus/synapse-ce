package projectuc

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func branchRetentionService(t *testing.T, keep int) (*Service, *memory.ProjectAnalysisStore) {
	t.Helper()
	repo := memory.NewProjectRepository()
	src := project.SourceBinding{Kind: project.SourceGit, Value: "https://github.com/acme/widget", DefaultBranch: "main"}
	p, err := project.New("p1", "tenant-a", "App", "app", src, nil, "", time.Unix(0, 0))
	if err != nil {
		t.Fatalf("new project: %v", err)
	}
	if err := repo.Create(context.Background(), p); err != nil {
		t.Fatalf("create project: %v", err)
	}
	store := memory.NewProjectAnalysisStore()
	svc := NewService(repo, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(store)
	svc.SetShortLivedBranchKeep(keep)
	return svc, store
}

func seedBranch(t *testing.T, store *memory.ProjectAnalysisStore, branch string, ids ...string) {
	t.Helper()
	for i, id := range ids {
		a := projectanalysis.Analysis{ID: id, TenantID: "tenant-a", ProjectID: "p1", CreatedAt: time.Unix(int64(i+1), 0), SourceRef: branch}
		if err := store.SaveWithResult(context.Background(), a, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBranchesClassifiesAgainstProjectDefault(t *testing.T) {
	svc, store := branchRetentionService(t, 20)
	seedBranch(t, store, "main", "m1")
	seedBranch(t, store, "feature/login", "f1")

	branches, err := svc.Branches(context.Background(), "tenant-a", "app")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]projectanalysis.BranchKind{}
	for _, b := range branches {
		kinds[b.Name] = b.Kind
	}
	if kinds["main"] != projectanalysis.BranchLongLived {
		t.Fatalf("main kind = %q, want long_lived", kinds["main"])
	}
	if kinds["feature/login"] != projectanalysis.BranchShortLived {
		t.Fatalf("feature/login kind = %q, want short_lived", kinds["feature/login"])
	}
}

func TestPruneShortLivedBranchRetiresOldAnalyses(t *testing.T) {
	svc, store := branchRetentionService(t, 2)
	seedBranch(t, store, "feature/x", "x1", "x2", "x3", "x4")
	seedBranch(t, store, "main", "m1", "m2", "m3")
	p, err := svc.Get(context.Background(), "tenant-a", "app")
	if err != nil {
		t.Fatal(err)
	}

	svc.pruneShortLivedBranch(context.Background(), p, "feature/x")
	feat, _, err := store.List(context.Background(), "tenant-a", "p1", "feature/x", 10, time.Time{}, "")
	if err != nil || len(feat) != 2 {
		t.Fatalf("feature analyses after prune = %d, want 2", len(feat))
	}

	// A long-lived branch is never pruned even with keep=2.
	svc.pruneShortLivedBranch(context.Background(), p, "main")
	main, _, err := store.List(context.Background(), "tenant-a", "p1", "main", 10, time.Time{}, "")
	if err != nil || len(main) != 3 {
		t.Fatalf("main analyses after prune = %d, want 3 (long-lived retained in full)", len(main))
	}
}

func TestPruneShortLivedBranchKeepsJustWrittenNewestAtBoundary(t *testing.T) {
	svc, store := branchRetentionService(t, 3)
	// keep+1 analyses; oldest is deleted, and the newest (last written) must survive.
	seedBranch(t, store, "feature/x", "x1", "x2", "x3", "x4")
	p, err := svc.Get(context.Background(), "tenant-a", "app")
	if err != nil {
		t.Fatal(err)
	}
	svc.pruneShortLivedBranch(context.Background(), p, "feature/x")
	feat, _, err := store.List(context.Background(), "tenant-a", "p1", "feature/x", 10, time.Time{}, "")
	if err != nil || len(feat) != 3 || feat[0].ID != "x4" {
		t.Fatalf("after boundary prune = %+v, want the newest 3 with x4 retained", feat)
	}
	for _, a := range feat {
		if a.ID == "x1" {
			t.Fatal("the oldest analysis must have been pruned")
		}
	}
}

func TestPruneSkippedWhenProjectHasNoDefaultBranch(t *testing.T) {
	repo := memory.NewProjectRepository()
	// A git project with neither Ref nor DefaultBranch set: the mainline signal is absent.
	src := project.SourceBinding{Kind: project.SourceGit, Value: "https://github.com/acme/widget"}
	p, err := project.New("p1", "tenant-a", "App", "app", src, nil, "", time.Unix(0, 0))
	if err != nil {
		t.Fatalf("new project: %v", err)
	}
	if err := repo.Create(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	store := memory.NewProjectAnalysisStore()
	svc := NewService(repo, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(store)
	svc.SetShortLivedBranchKeep(1)
	// "production" is a real mainline here; with no default branch it must not be pruned.
	seedBranch(t, store, "production", "p1a", "p2a", "p3a")
	svc.pruneShortLivedBranch(context.Background(), p, "production")
	got, _, err := store.List(context.Background(), "tenant-a", "p1", "production", 10, time.Time{}, "")
	if err != nil || len(got) != 3 {
		t.Fatalf("production analyses = %d, want 3 retained when the default branch is unknown", len(got))
	}
}

func TestPruneShortLivedBranchDisabledWhenKeepZero(t *testing.T) {
	svc, store := branchRetentionService(t, 0)
	seedBranch(t, store, "feature/x", "x1", "x2", "x3")
	p, err := svc.Get(context.Background(), "tenant-a", "app")
	if err != nil {
		t.Fatal(err)
	}
	svc.pruneShortLivedBranch(context.Background(), p, "feature/x")
	feat, _, err := store.List(context.Background(), "tenant-a", "p1", "feature/x", 10, time.Time{}, "")
	if err != nil || len(feat) != 3 {
		t.Fatalf("feature analyses = %d, want 3 (pruning disabled)", len(feat))
	}
}
