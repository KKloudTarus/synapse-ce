package projectuc

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceartifact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type cancelingSourceAnalysisStore struct {
	*memory.ProjectAnalysisStore
	cancel context.CancelFunc
}

func (s *cancelingSourceAnalysisStore) AttachSourceWithAudit(context.Context, shared.ID, shared.ID, shared.ID, projectanalysis.SourceCapture, ports.AuditEntry) error {
	s.cancel()
	return context.Canceled
}

func TestPublishSourceCompensatesArtifactAfterRequestCancellation(t *testing.T) {
	projects := memory.NewProjectRepository()
	baseAnalyses := memory.NewProjectAnalysisStore()
	ctx, cancel := context.WithCancel(context.Background())
	analyses := &cancelingSourceAnalysisStore{ProjectAnalysisStore: baseAnalyses, cancel: cancel}
	artifacts := sourceartifact.New(t.TempDir(), 0, 0, 0)
	svc := NewService(projects, memory.NewEngagementRepository(), sourcePublishTestClock(), fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetSourceArtifactStore(artifacts)

	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	analysis := projectanalysis.Analysis{
		ID: "cancel-analysis", TenantID: p.TenantID.String(), ProjectID: p.ID.String(), ProjectKey: p.Key,
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
		Capabilities: projectanalysis.SourceCapabilities{
			Source:       projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
			Comparison:   projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			UnifiedDiff:  projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			SplitDiff:    projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			Highlighting: projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
		},
		Snapshot: measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}},
	}
	if err := baseAnalyses.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}

	_, err = svc.PublishSource(ctx, PublishSourceInput{
		TenantID: p.TenantID, ProjectKey: p.Key, AnalysisID: analysis.ID,
		Actor: "ci-bot", ToolVersion: "test", Archive: sourceTar(t, map[string]string{"main.go": "package main\n"}),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("publish error=%v, want canceled attach", err)
	}
	if _, _, err := artifacts.Load(context.Background(), p.TenantID, p.ID, analysis.ID, "main.go"); !errors.Is(err, projectanalysis.ErrSourceNotRetained) {
		t.Fatalf("artifact survived canceled DB/audit attach: %v", err)
	}
	got, err := baseAnalyses.Get(context.Background(), p.TenantID, p.ID, shared.ID(analysis.ID))
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities.Source.Available || got.SourceManifest.Digest != "" {
		t.Fatalf("analysis changed despite canceled attach: %+v", got.SourceManifest)
	}
}
