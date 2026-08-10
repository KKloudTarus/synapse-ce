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
)

func TestPublishSourceRejectsPackageOnlyAnalysisInUsecase(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := &sourceAuditAnalysisStore{ProjectAnalysisStore: memory.NewProjectAnalysisStore()}
	artifacts := sourceartifact.New(t.TempDir(), 0, 0, 0)
	svc := NewService(projects, memory.NewEngagementRepository(), sourcePublishTestClock(), fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetSourceArtifactStore(artifacts)
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	analysis := projectanalysis.Analysis{
		ID: "package-only", TenantID: p.TenantID.String(), ProjectID: p.ID.String(), ProjectKey: p.Key,
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindArchive, Head: "app.jar"},
		Snapshot:       measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}}},
	}
	if err := analyses.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PublishSource(ctx, PublishSourceInput{
		TenantID: p.TenantID, ProjectKey: p.Key, AnalysisID: analysis.ID,
		Actor: "ci-bot", ToolVersion: "test", Archive: sourceTar(t, map[string]string{"app.jar": "not source"}),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("package-only publish error=%v, want validation", err)
	}
	if len(analyses.audits) != 0 {
		t.Fatalf("package-only target emitted audit: %+v", analyses.audits)
	}
	if _, _, err := artifacts.Load(ctx, p.TenantID, p.ID, analysis.ID, "app.jar"); !errors.Is(err, projectanalysis.ErrSourceNotRetained) {
		t.Fatalf("package-only target created artifact: %v", err)
	}
}
