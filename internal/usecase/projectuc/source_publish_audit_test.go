package projectuc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceartifact"
)

func TestPublishSourceFailsClosedWithoutTransactionalAuditStore(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := memory.NewProjectAnalysisStore()
	artifacts := sourceartifact.New(t.TempDir(), 0, 0, 0)
	svc := NewService(projects, memory.NewEngagementRepository(), sourcePublishTestClock(), fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetSourceArtifactStore(artifacts)
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	analysis := projectanalysis.Analysis{
		ID: "analysis", TenantID: p.TenantID.String(), ProjectID: p.ID.String(), ProjectKey: p.Key,
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
		Snapshot:       measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}},
	}
	if err := analyses.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	_, err = svc.PublishSource(ctx, PublishSourceInput{
		TenantID: p.TenantID, ProjectKey: p.Key, AnalysisID: analysis.ID,
		Actor: "ci-bot", ToolVersion: "test", Archive: sourceTar(t, map[string]string{"main.go": "package main\n"}),
	})
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "transactional source publication") {
		t.Fatalf("error=%v, want fail-closed transactional-audit validation", err)
	}
	if _, _, err := artifacts.Load(ctx, p.TenantID, p.ID, analysis.ID, "main.go"); !errors.Is(err, projectanalysis.ErrSourceNotRetained) {
		t.Fatalf("source artifact exists without durable audit support: %v", err)
	}
}
