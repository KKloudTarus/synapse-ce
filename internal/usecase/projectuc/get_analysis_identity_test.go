package projectuc

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

// An analysis read back must name the project it belongs to.
//
// The store keys analyses by project id and has no column for the key, so an analysis saved
// without one comes back without one. The CLI's publish-source refuses to stream a working tree
// unless the analysis the server returns names the project it was asked for, and against an empty
// key that check could never pass: the subcommand failed with "server returned an incompatible
// source analysis" for every project on every server.
func TestGetAnalysisNamesItsProject(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := NewService(projects, memory.NewEngagementRepository(), sourcePublishTestClock(), fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)

	p, err := svc.Create(ctx, CreateInput{
		TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project",
		SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Saved the way the CLI push records one: identified by project id, with no key of its own.
	if err := analyses.Save(ctx, projectanalysis.Analysis{
		ID: "analysis-1", TenantID: p.TenantID.String(), ProjectID: p.ID.String(),
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := svc.GetAnalysis(ctx, p.TenantID, p.Key, "analysis-1")
	if err != nil {
		t.Fatalf("get analysis: %v", err)
	}
	if got.ProjectKey != p.Key {
		t.Fatalf("project key = %q, want %q: a caller cannot verify it got the analysis it asked for", got.ProjectKey, p.Key)
	}
}
