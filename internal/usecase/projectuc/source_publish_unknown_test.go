package projectuc

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceartifact"
)

func TestPublishSourceRejectsUnknownAnalysisBeforeArtifactCreation(t *testing.T) {
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
	const missingAnalysis = "missing-analysis"
	_, err = svc.PublishSource(ctx, PublishSourceInput{
		TenantID: p.TenantID, ProjectKey: p.Key, AnalysisID: missingAnalysis,
		Actor: "ci-bot", ToolVersion: "test", Archive: sourceTar(t, map[string]string{"main.go": "package main\n"}),
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown analysis error=%v, want not found", err)
	}
	if len(analyses.audits) != 0 {
		t.Fatalf("unknown analysis emitted audit: %+v", analyses.audits)
	}
	if _, _, err := artifacts.Load(ctx, p.TenantID, p.ID, missingAnalysis, "main.go"); !errors.Is(err, projectanalysis.ErrSourceNotRetained) {
		t.Fatalf("unknown analysis created artifact: %v", err)
	}
}
