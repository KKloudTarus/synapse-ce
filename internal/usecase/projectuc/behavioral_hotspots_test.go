package projectuc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestGetBehavioralHotspotsPinnedRanking(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := newTestService(projects, analyses)
	p, err := svc.Create(ctx, CreateInput{
		TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project",
		SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"},
	})
	if err != nil {
		t.Fatal(err)
	}

	head := strings.Repeat("a", 40)
	parent := strings.Repeat("b", 40)
	report := &measure.BehavioralHotspotsReport{
		Version: measure.BehavioralHotspotsSchemaVersion, Availability: measure.BehavioralPartial,
		Reason: "1_of_3_files_unmeasured", HeadCommit: head, RequestedCommits: 2, EvaluatedCommits: 2, ReachedRoot: true,
		Commits: []measure.BehavioralCommitEvidence{
			{CommitID: head, FirstParentID: parent, TouchedPaths: []string{"src/a.go", "src/deep/hot.go"}},
			{CommitID: parent, TouchedPaths: []string{"src/deep/hot.go"}},
		},
		Files: []measure.BehavioralFile{
			{Path: "src/deep/hot.go", Language: "Go", Cyclomatic: 20, ChangeCount: 2, Score: 40},
			{Path: "src/a.go", Language: "Go", Cyclomatic: 5, ChangeCount: 1, Score: 5},
		},
		TotalEligible: 3, TotalMeasured: 2,
		Gaps: []measure.BehavioralGap{{Path: "src/unsupported.xyz", Reason: "complexity_not_measured"}},
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	analysis := projectanalysis.Analysis{
		ID: "analysis-1", TenantID: "tenant", ProjectID: p.ID.String(), ProjectKey: p.Key,
		CreatedAt: time.Now(), SourceRef: "main", SourceCommit: head, BehavioralHotspots: report,
		Snapshot: measure.Snapshot{Nodes: []measure.Node{
			{Path: "", Kind: measure.NodeProject},
			{Path: "src", Parent: "", Kind: measure.NodeDirectory},
			{Path: "src/a.go", Parent: "src", Kind: measure.NodeFile},
			{Path: "src/deep", Parent: "src", Kind: measure.NodeDirectory},
			{Path: "src/deep/hot.go", Parent: "src/deep", Kind: measure.NodeFile},
			{Path: "src/unsupported.xyz", Parent: "src", Kind: measure.NodeFile},
		}},
	}
	if err := analyses.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}

	res, err := svc.GetBehavioralHotspots(ctx, "tenant", "project", "analysis-1", "src", 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Analysis.ID != "analysis-1" || res.Analysis.SourceCommit != head || res.Availability != measure.BehavioralPartial {
		t.Fatalf("metadata=%+v", res)
	}
	if res.TotalEligible != 3 || res.TotalMeasured != 2 || res.TotalExcluded != 1 || res.Shown != 1 || res.Omitted != 1 {
		t.Fatalf("counts=%+v", res)
	}
	if len(res.Items) != 1 || res.Items[0].Path != "src/deep/hot.go" || res.Items[0].Score != 40 {
		t.Fatalf("items=%+v", res.Items)
	}

	if _, err := svc.GetBehavioralHotspots(ctx, "tenant", "project", "analysis-1", "src/../src", 50); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("non-canonical path error=%v", err)
	}
	if _, err := svc.GetBehavioralHotspots(ctx, "tenant", "project", "analysis-1", "missing", 50); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing path error=%v", err)
	}
	if _, err := svc.GetBehavioralHotspots(ctx, "other-tenant", "project", "analysis-1", "", 50); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant error=%v", err)
	}
}

func TestGetBehavioralHotspotsLegacyAnalysis(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := newTestService(projects, analyses)
	p, err := svc.Create(ctx, CreateInput{
		TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project",
		SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := analyses.Save(ctx, projectanalysis.Analysis{
		ID: "legacy", TenantID: "tenant", ProjectID: p.ID.String(), CreatedAt: time.Now(),
		Snapshot: measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}}},
	}); err != nil {
		t.Fatal(err)
	}
	res, err := svc.GetBehavioralHotspots(ctx, "tenant", "project", "legacy", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if res.Availability != measure.BehavioralUnavailable || res.Reason == nil || *res.Reason != "legacy_analysis" || len(res.Items) != 0 {
		t.Fatalf("legacy response=%+v", res)
	}
}
