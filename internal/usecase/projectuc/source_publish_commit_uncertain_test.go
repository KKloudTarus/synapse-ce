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

type uncertainCommitAnalysisStore struct {
	*memory.ProjectAnalysisStore
}

func (*uncertainCommitAnalysisStore) AttachSourceWithAudit(context.Context, shared.ID, shared.ID, shared.ID, projectanalysis.SourceCapture, ports.AuditEntry) error {
	return ports.ErrProjectSourceCommitUncertain
}

func TestPublishSourcePreservesArtifactWhenCommitOutcomeIsUncertain(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := &uncertainCommitAnalysisStore{ProjectAnalysisStore: memory.NewProjectAnalysisStore()}
	artifacts := sourceartifact.New(t.TempDir(), 0, 0, 0)
	svc := NewService(projects, memory.NewEngagementRepository(), sourcePublishTestClock(), fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetSourceArtifactStore(artifacts)

	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	analysis := projectanalysis.Analysis{
		ID: "uncertain-analysis", TenantID: p.TenantID.String(), ProjectID: p.ID.String(), ProjectKey: p.Key,
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
	if err := analyses.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}

	_, err = svc.PublishSource(ctx, PublishSourceInput{
		TenantID: p.TenantID, ProjectKey: p.Key, AnalysisID: analysis.ID,
		Actor: "ci-bot", ToolVersion: "test", Archive: sourceTar(t, map[string]string{"main.go": "package main\n"}),
	})
	if !errors.Is(err, ports.ErrProjectSourceCommitUncertain) {
		t.Fatalf("PublishSource() error=%v, want uncertain commit", err)
	}
	data, _, loadErr := artifacts.Load(ctx, p.TenantID, p.ID, analysis.ID, "main.go")
	if loadErr != nil {
		t.Fatalf("published artifact was destructively compensated: %v", loadErr)
	}
	if string(data) != "package main\n" {
		t.Fatalf("retained data=%q", data)
	}
}
