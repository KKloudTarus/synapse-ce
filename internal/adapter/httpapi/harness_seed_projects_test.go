package httpapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
)

// The projects group: the project analysis history, its issue and hotspot projections, its measures
// and overview, and the source findings recorded under the project's analysis context. Everything is
// planted for project-a (tenantA) through the real project service and the real in-memory analysis
// store, so a tenantB read of any of these routes is proven to find nothing rather than assumed to.
//
// The code, status and dependency-graph routes of the same project need a stored source file, a scan
// job and an SBOM that this seed does not plant; the "projx" seed seeds them.
func init() {
	registerHarnessSeed(harnessSeed{
		Name: "projects",
		Routes: []string{
			"GET /api/v1/projects/{key}/analyses",
			"GET /api/v1/projects/{key}/analyses/{id}",
			"GET /api/v1/projects/{key}/analyses/{id}/code/files",
			"GET /api/v1/projects/{key}/analysis",
			"GET /api/v1/projects/{key}/branches",
			"GET /api/v1/projects/{key}/hotspots",
			"GET /api/v1/projects/{key}/hotspots/{id}",
			"GET /api/v1/projects/{key}/hotspots/{id}/history",
			"GET /api/v1/projects/{key}/issues",
			"GET /api/v1/projects/{key}/issues/{id}",
			"GET /api/v1/projects/{key}/issues/{id}/history",
			"GET /api/v1/projects/{key}/measures",
			"GET /api/v1/projects/{key}/overview",
			"GET /api/v1/projects/{key}/source-findings",
			"GET /api/v1/projects/{key}/source-findings/{fid}",
		},
		Run: seedProjects,
	})
}

const (
	// projectsMarker appears in every response that serves the planted project data.
	projectsMarker = "tenantA-projects-marker"

	projectsTenant = shared.ID("tenantA")
)

func seedProjects(w *harnessWorld) []string {
	w.t.Helper()
	ctx := context.Background()
	key := harnessPathValues["{key}"]
	// The analysis id is the value the sweep substitutes for {id}, so /analyses/{id} and its code
	// routes address the planted analysis directly.
	analysisID := harnessPathValues["{id}"]
	now := time.Unix(1_700_000_000, 0).UTC()

	p, err := w.projects.Get(ctx, projectsTenant, key)
	if err != nil {
		w.t.Fatalf("projects seed: resolve %s: %v", key, err)
	}

	hotspotCandidate := hotspot.Candidate{
		Key: "projects-hotspot", FindingIdentity: "projects-hotspot", RuleKey: "projects-hotspot-rule",
		Title: projectsMarker + " hotspot", Description: "planted for the cross-tenant sweep",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST, Location: "src/" + projectsMarker + ".go:1",
	}
	issueCandidate := issue.Candidate{
		Key: "projects-issue", FindingIdentity: "projects-issue", RuleKey: "projects-issue-rule", Type: rule.TypeBug,
		Title: projectsMarker + " issue", Description: "planted for the cross-tenant sweep",
		Severity: shared.SeverityHigh, Kind: finding.KindReliability, Language: "go",
		File: projectsMarker + "/main.go", Location: projectsMarker + "/main.go:1",
	}
	analysis := projectanalysis.Analysis{
		ID: analysisID, TenantID: projectsTenant.String(), ProjectID: p.ID.String(), ProjectKey: p.Key,
		CreatedAt: now, Origin: projectanalysis.OriginServer,
		// The ref doubles as the branch name, so /branches and /analyses carry the marker too.
		SourceRef: projectsMarker, SourceCommit: "0123456789abcdef0123456789abcdef01234567",
		Measures: qualitygate.Snapshot{"new_issues": 1},
		Gate:     qualitygate.Result{Passed: true},
		GateInfo: projectanalysis.GateInfo{Name: "Quality gate", Source: "default"},
		Issues: projectanalysis.Counts{
			Total: 1, ByKind: map[string]int{string(finding.KindReliability): 1},
			BySeverity: map[string]int{string(shared.SeverityHigh): 1}, ByStatus: map[string]int{"open": 1},
		},
		NewCode: projectanalysis.NewCode{Counts: projectanalysis.Counts{
			Total: 1, ByKind: map[string]int{string(finding.KindReliability): 1},
			BySeverity: map[string]int{string(shared.SeverityHigh): 1}, ByStatus: map[string]int{"open": 1},
		}},
		Rating: rating.Report{Security: rating.GradeA, Reliability: rating.GradeB, Maintainability: rating.GradeA},
		// A directory named for the marker puts it in the children the measures route lists.
		Snapshot: measure.Snapshot{Nodes: []measure.Node{
			{Path: "", Name: p.Key, Kind: measure.NodeProject},
			{Path: projectsMarker, Name: projectsMarker, Kind: measure.NodeDirectory},
			{Path: projectsMarker + "/main.go", Name: "main.go", Kind: measure.NodeFile, Parent: projectsMarker, Language: "go"},
		}},
	}
	// The stored result has no SBOM on purpose: the dependency routes must keep answering 404.
	result, err := json.Marshal(map[string]any{"target": projectsMarker, "findings": []any{}})
	if err != nil {
		w.t.Fatalf("projects seed: encode analysis result: %v", err)
	}
	if err := w.analyses.SaveWithResultAndProjections(ctx, analysis, result,
		[]hotspot.Candidate{hotspotCandidate}, []issue.Candidate{issueCandidate}); err != nil {
		w.t.Fatalf("projects seed: save analysis: %v", err)
	}

	// The hotspot and issue ids are hashes of tenant, project and key, so the read stores go through
	// an alias for the sweep's {id}; the issue store was not wired by the fixture at all.
	alias := newProjectIDAlias(w.analyses, shared.ID(analysisID),
		hotspot.DeterministicID(projectsTenant, p.ID, hotspotCandidate.Key),
		issue.DeterministicID(projectsTenant, p.ID, issueCandidate.Key))
	w.projects.SetHotspotStore(alias)
	w.projects.SetIssueStore(alias)

	// One review decision on each, made through the real service, so the history routes have an
	// event that names the marker rather than an empty list.
	if _, _, err := w.projects.TransitionHotspot(ctx, projectsMarker, projectsTenant, key, alias.hotspotID,
		hotspot.StatusAcknowledged, projectsMarker+" reviewed", 1); err != nil {
		w.t.Fatalf("projects seed: review hotspot: %v", err)
	}
	if _, _, err := w.projects.TransitionIssue(ctx, projectsMarker, projectsTenant, key, alias.issueID,
		issue.StatusAccepted, projectsMarker+" triaged", 1); err != nil {
		w.t.Fatalf("projects seed: triage issue: %v", err)
	}

	seedProjectSourceFindings(w, key)
	return []string{projectsMarker}
}

// seedProjectSourceFindings records one source finding under the project's analysis context. The
// source-finding routes read through the router's findings service, which has no setter: it is
// created here only when no other seed has wired one, and an existing one is reused as it stands.
func seedProjectSourceFindings(w *harnessWorld, key string) {
	w.t.Helper()
	fid := harnessPathValues["{fid}"]
	// Create only when no seed has wired the service: another seed owns it otherwise, and replacing
	// it would turn that seed's routes vacuous. The service answers with the id its generator
	// yields, so a service built here hands out the sweep's {fid}.
	owned := w.rt.findings == nil
	if owned {
		w.rt.findings = findingsuc.NewService(memory.NewFindingRepository(), nil, nil, w.audit,
			fixedClock{t: time.Unix(1, 0)}, projectsFixedID(fid))
	}

	// The finding goes in through the service's own Create, into whatever repository it holds, under
	// the hidden engagement the project service resolves for the key.
	ctx := shared.WithTenant(context.Background(), projectsTenant)
	source, err := w.projects.SourceContext(ctx, projectsTenant, key)
	if err != nil {
		w.t.Fatalf("projects seed: resolve source context: %v", err)
	}
	created, err := w.rt.findings.Create(ctx, projectsMarker, source.Context.ID,
		finding.ManualInput{Title: projectsMarker + " source finding", Severity: shared.SeverityHigh})
	if err != nil {
		if owned {
			w.t.Fatalf("projects seed: plant source finding: %v", err)
		}
		w.t.Logf("projects seed: the shared findings service refused the source finding, so the source-finding routes stay empty: %v", err)
		return
	}
	if created.ID.String() != fid {
		w.t.Logf("projects seed: the shared findings service named the source finding %q, not the sweep's %q, so only the list route can serve it", created.ID, fid)
	}
}

// projectsFixedID is an id generator that always yields one value. The seed creates a single
// finding with it, so the finding lands on the id the generated sweep asks for.
type projectsFixedID string

func (id projectsFixedID) NewID() shared.ID { return shared.ID(id) }
