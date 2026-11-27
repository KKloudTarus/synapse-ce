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
)

// The projects group: the project analysis history, its behavioral hotspots, its issue and hotspot
// projections, its measures and overview. Everything is planted for project-a (tenantA) through the
// real project service and the real in-memory analysis store, so a tenantB read of any of these
// routes is proven to find nothing rather than assumed to.
//
// The code, status, source-scan and dependency-graph routes of the same project need a stored source
// file, a scan job and an SBOM that this seed does not plant; the "projx" seed seeds them. The
// project's source findings are served by the router's findings service, which the "core" seed wires,
// so that seed plants them and declares their routes.
func init() {
	registerHarnessSeed(harnessSeed{
		Name: "projects",
		Routes: []string{
			"GET /api/v1/projects/{key}/analyses",
			"GET /api/v1/projects/{key}/analyses/{analysisID}/behavioral-hotspots",
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
		},
		// The behavioral-hotspots route names the analysis with its own parameter. It is the analysis
		// this seed saves, which the other analysis routes address as {id}.
		PathValues: map[string]string{"{analysisID}": harnessPathValues["{id}"]},
		RoutePathValues: map[string]map[string]string{
			// A profile assignment names a language the quality catalog knows.
			"PUT /api/v1/projects/{key}/profiles/{language}": {"{language}": "go"},
		},
		Run: seedProjects,
	})
}

const (
	// projectsMarker appears in every response that serves the planted project data.
	projectsMarker = "tenantA-projects-marker"

	// projectsBehaviorMarker names the one file the planted behavioral-hotspots report ranks, so it
	// appears in a response only when that report was served, not merely the analysis around it.
	projectsBehaviorMarker = "tenantA-projects-behavior-marker"

	projectsTenant = shared.ID("tenantA")

	// projectsCommit is the head commit of the planted analysis and of its behavioral history.
	projectsCommit = "0123456789abcdef0123456789abcdef01234567"
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
	// One commit that touched one file, so the behavioral ranking has an item to serve. An analysis
	// without the report answers "legacy_analysis" and an empty list, which proves nothing about the
	// route. The report is checked here so a malformed fixture fails the seed, not the sweep.
	behaviorFile := projectsBehaviorMarker + "/hot.go"
	behavior := measure.BehavioralHotspotsReport{
		Version: measure.BehavioralHotspotsSchemaVersion, Availability: measure.BehavioralComplete,
		HeadCommit: projectsCommit, RequestedCommits: 1, EvaluatedCommits: 1, ReachedRoot: true,
		Commits:       []measure.BehavioralCommitEvidence{{CommitID: projectsCommit, TouchedPaths: []string{behaviorFile}}},
		Files:         []measure.BehavioralFile{{Path: behaviorFile, Language: "go", Cyclomatic: 4, ChangeCount: 1, Score: 4}},
		TotalEligible: 1, TotalMeasured: 1,
	}
	if err := behavior.Validate(); err != nil {
		w.t.Fatalf("projects seed: behavioral hotspots report: %v", err)
	}
	analysis := projectanalysis.Analysis{
		ID: analysisID, TenantID: projectsTenant.String(), ProjectID: p.ID.String(), ProjectKey: p.Key,
		CreatedAt: now, Origin: projectanalysis.OriginServer,
		// The ref doubles as the branch name, so /branches and /analyses carry the marker too.
		SourceRef: projectsMarker, SourceCommit: projectsCommit, BehavioralHotspots: &behavior,
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
		// A directory named for the marker puts it in the children the measures route lists. The
		// behavioral report ranks a file of its own, so the snapshot lists it as well.
		Snapshot: measure.Snapshot{Nodes: []measure.Node{
			{Path: "", Name: p.Key, Kind: measure.NodeProject},
			{Path: projectsMarker, Name: projectsMarker, Kind: measure.NodeDirectory},
			{Path: projectsMarker + "/main.go", Name: "main.go", Kind: measure.NodeFile, Parent: projectsMarker, Language: "go"},
			{Path: projectsBehaviorMarker, Name: projectsBehaviorMarker, Kind: measure.NodeDirectory},
			{Path: behaviorFile, Name: "hot.go", Kind: measure.NodeFile, Parent: projectsBehaviorMarker, Language: "go"},
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

	return []string{projectsMarker, projectsBehaviorMarker}
}
