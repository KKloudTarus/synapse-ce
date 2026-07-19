package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestProjectAnalysisStoreClonesMutableSnapshots(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	analysis := projectanalysis.Analysis{
		ID: "a1", TenantID: "tenant", ProjectID: "project", Measures: qualitygate.Snapshot{"coverage": 50},
		Gate:           qualitygate.Result{Results: []qualitygate.ConditionResult{{Actual: 50}}},
		Issues:         projectanalysis.Counts{ByKind: map[string]int{"sca": 1}, BySeverity: map[string]int{"high": 1}, ByStatus: map[string]int{"open": 1}},
		InternalIssues: []projectanalysis.Issue{{Key: "key", Kind: finding.KindSCA}},
		NewCode:        projectanalysis.NewCode{Counts: projectanalysis.Counts{ByKind: map[string]int{"sca": 1}, BySeverity: map[string]int{}, ByStatus: map[string]int{}}},
		Delta:          &projectanalysis.Delta{Measures: map[string]float64{"coverage": 1}, Ratings: map[string]int{"security": 1}, Issues: projectanalysis.Counts{ByKind: map[string]int{}, BySeverity: map[string]int{}, ByStatus: map[string]int{}}},
		Coverage:       &measure.CoverageReport{Files: []measure.FileCoverage{{File: "a.go", CoveredLines: 5, TotalLines: 10}}},
		Duplication:    measure.DuplicationReport{Blocks: []measure.DuplicationBlock{{Occurrences: []measure.CodeRange{{File: "a.go", StartLine: 1, EndLine: 2}}}}},
		Rating:         rating.Report{Security: rating.GradeA},
		Snapshot: measure.Snapshot{
			Nodes: []measure.Node{
				{
					Path: "src/a.go",
					Counters: measure.Counters{
						IssuesByType: map[string]int{"bug": 1},
					},
				},
			},
			NewCodeCoverage: measure.DecimalMetric{Value: new(float64)},
		},
	}
	*analysis.Snapshot.NewCodeCoverage.Value = 10.0

	if err := store.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	analysis.Measures["coverage"] = 0
	analysis.Coverage.Files[0].File = "mutated.go"
	analysis.Duplication.Blocks[0].Occurrences[0].File = "mutated.go"
	analysis.Snapshot.Nodes[0].Counters.IssuesByType["bug"] = 0
	*analysis.Snapshot.NewCodeCoverage.Value = 0.0

	got, err := store.Get(ctx, "tenant", "project", "a1")
	if err != nil {
		t.Fatal(err)
	}
	got.Measures["coverage"] = 0
	got.Issues.ByKind["sca"] = 0
	got.Gate.Results[0].Actual = 0
	got.Coverage.Files[0].File = "returned.go"
	got.Duplication.Blocks[0].Occurrences[0].File = "returned.go"
	got.Delta.Measures["coverage"] = 0
	got.Snapshot.Nodes[0].Counters.IssuesByType["bug"] = 0
	*got.Snapshot.NewCodeCoverage.Value = 0.0

	list, _, err := store.List(ctx, "tenant", "project", 1, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if list[0].Measures["coverage"] != 50 || list[0].Issues.ByKind["sca"] != 1 || list[0].Gate.Results[0].Actual != 50 || list[0].Coverage.Files[0].File != "a.go" || list[0].Duplication.Blocks[0].Occurrences[0].File != "a.go" || list[0].Delta.Measures["coverage"] != 1 {
		t.Fatalf("stored snapshot mutated: %+v", list[0])
	}
	if list[0].Snapshot.Nodes[0].Counters.IssuesByType["bug"] != 1 {
		t.Fatalf("snapshot node counters mutated")
	}
	if list[0].Snapshot.NewCodeCoverage.Value == nil || *list[0].Snapshot.NewCodeCoverage.Value != 10.0 {
		t.Fatalf("snapshot new code coverage mutated")
	}
}

func TestProjectAnalysisStoreLatestResultStaysWithSnapshot(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	old := projectanalysis.Analysis{ID: "old", TenantID: "tenant", ProjectID: "project", CreatedAt: time.Unix(1, 0)}
	latest := projectanalysis.Analysis{ID: "latest", TenantID: "tenant", ProjectID: "project", CreatedAt: time.Unix(2, 0)}
	if err := store.SaveWithResult(ctx, old, []byte(`{"run":"old"}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveWithResult(ctx, latest, []byte(`{"run":"latest"}`)); err != nil {
		t.Fatal(err)
	}
	got, result, err := store.LatestWithResult(ctx, "tenant", "project")
	if err != nil || got.ID != "latest" || string(result) != `{"run":"latest"}` {
		t.Fatalf("analysis=%+v result=%s err=%v", got, result, err)
	}
}

func TestProjectAnalysisStoreLatestResultSkipsMetadataOnlySnapshot(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	withResult := projectanalysis.Analysis{ID: "with-result", TenantID: "tenant", ProjectID: "project", CreatedAt: time.Unix(1, 0)}
	metadataOnly := projectanalysis.Analysis{ID: "metadata-only", TenantID: "tenant", ProjectID: "project", CreatedAt: time.Unix(2, 0)}
	if err := store.SaveWithResult(ctx, withResult, []byte(`{"run":"complete"}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, metadataOnly); err != nil {
		t.Fatal(err)
	}
	got, result, err := store.LatestWithResult(ctx, "tenant", "project")
	if err != nil || got.ID != withResult.ID || string(result) != `{"run":"complete"}` {
		t.Fatalf("analysis=%+v result=%s err=%v", got, result, err)
	}
}

func TestProjectAnalysisStoreScopesAndOrdersSnapshots(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	old := projectanalysis.Analysis{ID: "old", TenantID: "tenant-a", ProjectID: "project-a", CreatedAt: time.Unix(1, 0)}
	latestA := projectanalysis.Analysis{ID: "latest-a", TenantID: "tenant-a", ProjectID: "project-a", CreatedAt: time.Unix(2, 0)}
	latestB := projectanalysis.Analysis{ID: "latest-b", TenantID: "tenant-a", ProjectID: "project-a", CreatedAt: time.Unix(2, 0)}
	other := projectanalysis.Analysis{ID: "other", TenantID: "tenant-b", ProjectID: "project-b", CreatedAt: time.Unix(3, 0)}
	for _, analysis := range []projectanalysis.Analysis{old, latestA, other, latestB, latestB} {
		if err := store.Save(ctx, analysis); err != nil {
			t.Fatal(err)
		}
	}
	list, more, err := store.List(ctx, "tenant-a", "project-a", 2, time.Time{}, "")
	if err != nil || !more || len(list) != 2 || list[0].ID != "latest-b" || list[1].ID != "latest-a" {
		t.Fatalf("list=%+v more=%v err=%v", list, more, err)
	}
	next, more, err := store.List(ctx, "tenant-a", "project-a", 2, list[1].CreatedAt, shared.ID(list[1].ID))
	if err != nil || more || len(next) != 1 || next[0].ID != "old" {
		t.Fatalf("next=%+v more=%v err=%v", next, more, err)
	}
	if _, err := store.Get(ctx, "tenant-a", "project-a", "other"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-project read=%v, want not found", err)
	}
}
