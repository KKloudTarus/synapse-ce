package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceartifact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The projx group finishes the project routes the "projects" seed leaves empty: the code viewer
// (file and diff), the analysis status, the source-scan job, the dependency graph and its CycloneDX
// export. The code and dependency routes read the analysis the "projects" seed saved for project-a,
// which the store keeps append-only, so this seed does not plant a second one: it extends that
// analysis on the way out of the store, with a source file, a base to compare against and an SBOM of
// its own. It names nothing the "projects" seed defines except that the analysis exists, which it
// checks, and the sweep's {id} the analysis is saved under.
func init() {
	registerHarnessSeed(harnessSeed{
		Name: "projx",
		Routes: []string{
			"GET /api/v1/projects/{key}/analyses/{id}/code/diff",
			"GET /api/v1/projects/{key}/analyses/{id}/code/file",
			"GET /api/v1/projects/{key}/analysis-status",
			"GET /api/v1/projects/{key}/dependency-graph",
			"GET /api/v1/projects/{key}/dependency-graph/export",
			"GET /api/v1/projects/{key}/source-scans/{jobID}",
		},
		// The source-scan route names the planted job with its own parameter.
		PathValues: map[string]string{"{jobID}": projxSourceScanJobID},
		Queries: map[string]string{
			"GET /api/v1/projects/{key}/analyses/{id}/code/diff": "?path=" + projxCodePath,
			"GET /api/v1/projects/{key}/analyses/{id}/code/file": "?path=" + projxCodePath,
		},
		Run: seedProjx,
	})
}

const (
	// projxMarker appears in every response that serves the data this seed plants.
	projxMarker = "tenantA-projx-marker"

	projxTenant = shared.ID("tenantA")

	// projxCodePath is the file this seed adds to the analysis snapshot and retains the source of.
	// The code routes serve a file only when the snapshot lists it, so it is listed under a directory
	// named for the marker, as the snapshot's other directories are.
	projxCodePath = projxMarker + "/main.go"

	projxCommit    = "0123456789abcdef0123456789abcdef01234567"
	projxBaseSHA   = "89abcdef0123456789abcdef0123456789abcdef"
	projxJobID     = "projx-job-A"
	projxHeadLines = "package main\n\n// " + projxMarker + ": retained source for the cross-tenant sweep\nfunc main() {}\n"
	projxBaseLines = "package main\n\nfunc main() {}\n"

	// projxSourceScanJobID is the project's source-scan job. It is admitted with the source-scan
	// purpose, so the analysis-status route, which skips those jobs, keeps reading projxJobID.
	projxSourceScanJobID = "projx-source-scan-A"
)

func seedProjx(w *harnessWorld) []string {
	w.t.Helper()
	ctx := context.Background()
	key := harnessPathValues["{key}"]
	analysisID := shared.ID(harnessPathValues["{id}"])

	p, err := w.projects.Get(ctx, projxTenant, key)
	if err != nil {
		w.t.Fatalf("projx seed: resolve %s: %v", key, err)
	}
	// The planted analysis is the one this seed extends. Without it the routes below would be
	// asked about an analysis that does not exist, so say so here rather than report five 404s.
	if _, err := w.analyses.Get(ctx, projxTenant, p.ID, analysisID); err != nil {
		w.t.Fatalf("projx seed: the projects seed must plant analysis %s first: %v", analysisID, err)
	}

	store := sourceartifact.New(w.t.TempDir(), 0, 0, 0)
	head, base := projxRetainSource(w, store, p.ID, analysisID)
	w.projects.SetSourceArtifactStore(store)

	dependencies, err := json.Marshal(&sbom.SBOM{
		TargetRef: projxMarker,
		Components: []sbom.Component{
			{Name: projxMarker + "-app", Version: "1.0.0", PURL: "pkg:generic/" + projxMarker + "-app@1.0.0"},
			{Name: projxMarker + "-lib", Version: "2.1.0", PURL: "pkg:generic/" + projxMarker + "-lib@2.1.0"},
		},
		Dependencies: []sbom.Dependency{{
			Ref:       "pkg:generic/" + projxMarker + "-app@1.0.0",
			DependsOn: []string{"pkg:generic/" + projxMarker + "-lib@2.1.0"},
		}},
	})
	if err != nil {
		w.t.Fatalf("projx seed: encode SBOM: %v", err)
	}
	// The store keeps an analysis append-only, so the analysis the "projects" seed saved cannot gain
	// source, a comparison base or an SBOM by being saved again. The service reads through this
	// wrapper instead: it asks the real store, which still scopes by tenant and project, and adds
	// the planted source and SBOM only to what that store returned.
	w.projects.SetAnalysisStore(projxAnalyses{
		ProjectAnalysisStore: w.analyses,
		id:                   analysisID.String(),
		head:                 head,
		base:                 base,
		sbom:                 dependencies,
	})

	seedProjxJobs(w, key)
	return []string{projxMarker}
}

// projxRetainSource captures the head and base source of the analysis through the real artifact
// store, which writes content-addressed blobs and a manifest under a temporary directory. It returns
// the two manifests the analysis must carry for the viewer to find and verify the bytes.
func projxRetainSource(w *harnessWorld, store *sourceartifact.Store, projectID, analysisID shared.ID) (projectanalysis.SourceManifest, projectanalysis.SourceManifest) {
	w.t.Helper()
	ctx := context.Background()
	src := w.t.TempDir()
	file := filepath.Join(src, filepath.FromSlash(projxCodePath))
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		w.t.Fatalf("projx seed: create source directory: %v", err)
	}
	if err := os.WriteFile(file, []byte(projxHeadLines), 0o600); err != nil {
		w.t.Fatalf("projx seed: write source file: %v", err)
	}
	capture, err := store.Capture(ctx, projxTenant, projectID, analysisID.String(), src)
	if err != nil {
		w.t.Fatalf("projx seed: capture head source: %v", err)
	}
	base, err := store.CaptureBase(ctx, projxTenant, projectID, analysisID.String(), map[string][]byte{projxCodePath: []byte(projxBaseLines)})
	if err != nil {
		w.t.Fatalf("projx seed: capture base source: %v", err)
	}
	return capture.Manifest, base
}

// seedProjxJobs records two finished jobs under the hidden engagement the project service resolves
// for the key: the project's latest analysis job, which the status route reads, and a source-scan job,
// which the source-scan route reads. The store skips source-scan jobs when it answers the status, and
// the route answers a source-scan job only for the purpose it was admitted with, so each route reads
// its own job. The service takes the store through one setter, so both jobs go into one store.
func seedProjxJobs(w *harnessWorld, key string) {
	w.t.Helper()
	ctx := shared.WithTenant(context.Background(), projxTenant)
	source, err := w.projects.SourceContext(ctx, projxTenant, key)
	if err != nil {
		w.t.Fatalf("projx seed: resolve analysis context: %v", err)
	}
	jobs := memory.NewScanJobStore()
	started, finished := time.Unix(1_700_000_000, 0).UTC(), time.Unix(1_700_000_060, 0).UTC()
	for _, job := range []ports.ScanJob{
		{
			ID: projxJobID, EngagementID: source.Context.ID.String(), Target: projxMarker, Kind: ports.TargetLocal,
			Status: ports.ScanSucceeded, Stage: "done", Progress: 100, StartedAt: started, FinishedAt: &finished,
		},
		{
			ID: projxSourceScanJobID, EngagementID: source.Context.ID.String(), Target: projxMarker + "/source-scan", Kind: ports.TargetLocal,
			Purpose: ports.ScanPurposeProjectSource,
			Status:  ports.ScanSucceeded, Stage: "done", Progress: 100, StartedAt: started, FinishedAt: &finished,
		},
	} {
		// A running job holds the engagement's scan slot, so each is finished before the next is admitted.
		if err := jobs.CreateRunning(ctx, job); err != nil {
			w.t.Fatalf("projx seed: admit job %s: %v", job.ID, err)
		}
		if err := jobs.Save(ctx, job); err != nil {
			w.t.Fatalf("projx seed: finish job %s: %v", job.ID, err)
		}
	}
	w.projects.SetScanJobs(jobs)
}

// projxAnalyses is the analysis store the project service reads in this fixture. It embeds the real
// in-memory store, so tenant and project scoping, listing, projections and every optional store
// interface behave as before, and changes only how the planted analysis is returned.
type projxAnalyses struct {
	*memory.ProjectAnalysisStore
	id         string
	head, base projectanalysis.SourceManifest
	sbom       json.RawMessage
}

func (s projxAnalyses) Get(ctx context.Context, tenantID, projectID, analysisID shared.ID) (projectanalysis.Analysis, error) {
	analysis, err := s.ProjectAnalysisStore.Get(ctx, tenantID, projectID, analysisID)
	if err != nil {
		return projectanalysis.Analysis{}, err
	}
	return s.withSource(analysis), nil
}

func (s projxAnalyses) LatestWithResult(ctx context.Context, tenantID, projectID shared.ID, branch string) (projectanalysis.Analysis, []byte, error) {
	analysis, result, err := s.ProjectAnalysisStore.LatestWithResult(ctx, tenantID, projectID, branch)
	if err != nil || analysis.ID != s.id {
		return analysis, result, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(result, &document); err != nil {
		return projectanalysis.Analysis{}, nil, fmt.Errorf("decode planted analysis result: %w", err)
	}
	document["sbom"] = s.sbom
	merged, err := json.Marshal(document)
	if err != nil {
		return projectanalysis.Analysis{}, nil, fmt.Errorf("encode planted analysis result: %w", err)
	}
	return s.withSource(analysis), merged, nil
}

// withSource adds the retained source, the comparison base and one persisted file change to the
// planted analysis, and leaves any other analysis untouched. The retained file is listed in the
// snapshot too, because the code routes serve only the files the snapshot lists. The nodes go into a
// new slice: the one the store returned may be shared with the stored analysis.
func (s projxAnalyses) withSource(analysis projectanalysis.Analysis) projectanalysis.Analysis {
	if analysis.ID != s.id {
		return analysis
	}
	nodes := append([]measure.Node(nil), analysis.Snapshot.Nodes...)
	nodes = append(nodes,
		measure.Node{Path: projxMarker, Name: projxMarker, Kind: measure.NodeDirectory},
		measure.Node{Path: projxCodePath, Name: "main.go", Kind: measure.NodeFile, Parent: projxMarker, Language: "go"},
	)
	analysis.Snapshot.Nodes = nodes
	available := projectanalysis.Capability{Available: true}
	analysis.Capabilities = projectanalysis.SourceCapabilities{
		Source: available, Comparison: available, UnifiedDiff: available, SplitDiff: available, Highlighting: available,
	}
	analysis.SourceRevision = projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindGit, Head: projxCommit, Base: projxBaseSHA, MergeBase: projxBaseSHA}
	analysis.SourceManifest = s.head
	analysis.Comparison = projectanalysis.Comparison{
		Available: true, BaseRef: projxMarker, BaseCommit: projxBaseSHA, MergeBase: projxBaseSHA, BaseManifest: s.base,
	}
	analysis.FileChanges = []projectanalysis.FileChange{{
		Status: projectanalysis.FileStatusModified, OldPath: projxCodePath, NewPath: projxCodePath,
		Added: []projectanalysis.LineRange{{Start: 3, End: 3}},
		Hunks: []projectanalysis.DiffHunk{{
			OldStart: 1, OldLines: 3, NewStart: 1, NewLines: 4,
			Rows: []projectanalysis.DiffRow{
				{Kind: projectanalysis.DiffRowContext, OldLine: 1, NewLine: 1, Text: "package main"},
				{Kind: projectanalysis.DiffRowContext, OldLine: 2, NewLine: 2, Text: ""},
				{Kind: projectanalysis.DiffRowAdded, NewLine: 3, Text: "// " + projxMarker + ": retained source for the cross-tenant sweep"},
				{Kind: projectanalysis.DiffRowContext, OldLine: 3, NewLine: 4, Text: "func main() {}"},
			},
		}},
	}}
	return analysis
}
