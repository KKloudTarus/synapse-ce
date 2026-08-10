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

type tamperingSourceStore struct {
	*sourceartifact.Store
	tamper bool
}

func (s *tamperingSourceStore) Load(ctx context.Context, tenantID, projectID interfaceID, analysisID, path string) ([]byte, projectanalysis.SourceFile, error) {
	data, file, err := s.Store.Load(ctx, tenantID, projectID, analysisID, path)
	if err != nil || !s.tamper {
		return data, file, err
	}
	forged := file
	forged.Digest = "forged-digest"
	forged.Bytes = int64(len("tampered\n"))
	return []byte("tampered\n"), forged, nil
}

// interfaceID aliases shared.ID only to keep the override signature visually focused on the
// tampering behavior while still exactly satisfying ports.ProjectSourceArtifactStore.
type interfaceID = shared.ID

func TestReadCodeFileRejectsArtifactDetachedFromPersistedManifest(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := &sourceAuditAnalysisStore{ProjectAnalysisStore: memory.NewProjectAnalysisStore()}
	artifacts := &tamperingSourceStore{Store: sourceartifact.New(t.TempDir(), 0, 0, 0)}
	svc := NewService(projects, memory.NewEngagementRepository(), sourcePublishTestClock(), fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetSourceArtifactStore(artifacts)

	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	analysis := projectanalysis.Analysis{
		ID: "integrity-analysis", TenantID: p.TenantID.String(), ProjectID: p.ID.String(), ProjectKey: p.Key,
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
	if _, err := svc.PublishSource(ctx, PublishSourceInput{
		TenantID: p.TenantID, ProjectKey: p.Key, AnalysisID: analysis.ID,
		Actor: "ci-bot", ToolVersion: "test", Archive: sourceTar(t, map[string]string{"main.go": "package main\n"}),
	}); err != nil {
		t.Fatal(err)
	}

	artifacts.tamper = true
	if _, _, err := svc.ReadCodeFile(ctx, p.TenantID, p.Key, analysis.ID, "main.go", 1, 10); !errors.Is(err, projectanalysis.ErrSourceIntegrity) {
		t.Fatalf("tampered read error=%v, want source integrity", err)
	}
}
