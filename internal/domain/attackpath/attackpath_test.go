package attackpath

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const tenant = shared.ID("tenant")

func testAsset(id shared.ID, kind asset.Kind) asset.Asset {
	return asset.Asset{ID: id, TenantID: tenant, Kind: kind, Key: string(id), Name: string(id)}
}

func testGraph(t *testing.T) *Graph {
	t.Helper()
	g, err := NewGraph(Input{
		TenantID: tenant,
		Assets:   []asset.Asset{testAsset("exposure", asset.KindExposure), testAsset("web", asset.KindWorkload), testAsset("db", asset.KindStorage)},
		Edges: []asset.Edge{
			{TenantID: tenant, From: "exposure", To: "web", Kind: asset.EdgeExposes, Provenance: "obs-z", Confidence: asset.EdgeInferred},
			{TenantID: tenant, From: "exposure", To: "web", Kind: asset.EdgeExposes, Provenance: "obs-a", Confidence: asset.EdgeObserved},
			{TenantID: tenant, From: "web", To: "db", Kind: asset.EdgeReaches, Provenance: "obs-b", Confidence: asset.EdgeObserved},
			{TenantID: tenant, From: "db", To: "web", Kind: asset.EdgeReaches, Provenance: "obs-cycle", Confidence: asset.EdgeObserved},
		},
		Findings: []FindingInput{
			{Finding: finding.Finding{ID: "F-good", KEV: true, RiskScore: 7, Severity: shared.SeverityHigh, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, Reachability: judgment.Reachable, Tier: judgment.Tier2, Provenance: "reach-good", Confirmed: true},
			{Finding: finding.Finding{ID: "F-unknown", RiskScore: 8, Severity: shared.SeverityCritical}, Reachability: judgment.ReachUnknown, Tier: judgment.Tier1, Provenance: "reach-unknown", Confirmed: false},
			{Finding: finding.Finding{ID: "F-forbidden", RiskScore: 10, Severity: shared.SeverityCritical}, Reachability: judgment.NotReachable, Tier: judgment.Tier2, Provenance: "reach-no", Confirmed: true},
		},
		Bindings: []Binding{
			{AssetID: "db", FindingID: "F-good", Producer: "bind-good", Provenance: "bind-good", Confidence: asset.EdgeObserved},
			{AssetID: "web", FindingID: "F-unknown", Producer: "bind-unknown", Provenance: "bind-unknown", Confidence: asset.EdgeInferred},
			{AssetID: "web", FindingID: "F-forbidden", Producer: "bind-forbidden", Provenance: "bind-forbidden", Confidence: asset.EdgeObserved},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestNewGraphValidatesAndGroupsEvidence(t *testing.T) {
	if _, err := NewGraph(Input{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant error = %v", err)
	}
	g := testGraph(t)
	if len(g.Edges) != 6 {
		t.Fatalf("logical edges = %d, want 6", len(g.Edges))
	}
	var expose LogicalEdge
	for _, e := range g.Edges {
		if e.From == "exposure" && e.To == "web" {
			expose = e
		}
	}
	if !expose.Observed || len(expose.Evidence) != 2 || expose.Evidence[0].Provenance != "obs-a" {
		t.Fatalf("parallel evidence not canonicalized: %#v", expose)
	}
	bad := Input{TenantID: tenant, Assets: []asset.Asset{testAsset("a", asset.KindHost)}, Edges: []asset.Edge{{TenantID: tenant, From: "a", To: "missing", Kind: asset.EdgeRuns, Provenance: "p", Confidence: asset.EdgeObserved}}}
	if _, err := NewGraph(bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown endpoint error = %v", err)
	}
}

func TestDerivedEvidenceRetainsProducerAndChangesPathID(t *testing.T) {
	input := Input{
		TenantID: tenant,
		Assets:   []asset.Asset{testAsset("exposure", asset.KindExposure)},
		Findings: []FindingInput{{Finding: finding.Finding{ID: "F", Severity: shared.SeverityHigh}, Reachability: judgment.Reachable, Tier: judgment.Tier2, Provenance: "reach", Confirmed: true}},
		Bindings: []Binding{{AssetID: "exposure", FindingID: "F", Producer: "producer-b", Provenance: "immutable", Confidence: asset.EdgeObserved}, {AssetID: "exposure", FindingID: "F", Producer: "producer-a", Provenance: "immutable", Confidence: asset.EdgeObserved}},
	}
	graph, err := NewGraph(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Edges) != 1 || len(graph.Edges[0].Evidence) != 2 || graph.Edges[0].Evidence[0].Producer != "producer-a" || graph.Edges[0].Evidence[1].Producer != "producer-b" {
		t.Fatalf("derived evidence = %#v", graph.Edges)
	}
	paths, err := graph.Traverse(context.Background(), Query{}, Limits{})
	if err != nil || len(paths.Paths) != 1 {
		t.Fatalf("paths = %#v, %v", paths, err)
	}
	input.Bindings = input.Bindings[:1]
	graph, err = NewGraph(input)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := graph.Traverse(context.Background(), Query{}, Limits{})
	if err != nil || len(changed.Paths) != 1 || paths.Paths[0].ID == changed.Paths[0].ID {
		t.Fatalf("producer must affect path identity: %#v, %#v, %v", paths, changed, err)
	}
}

func TestTraverseFiltersUncertaintyAndFixtureExpectation(t *testing.T) {
	g := testGraph(t)
	got, err := g.Traverse(context.Background(), Query{}, Limits{MaxPaths: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Paths) != 2 {
		t.Fatalf("paths = %d, want 2", len(got.Paths))
	}
	if got.Paths[0].finding().Finding.ID != "F-good" || !got.Paths[0].Confident || len(got.Paths[0].Steps) != len(got.Paths[0].Edges) || got.Paths[0].Steps[0].Evidence[0].Provenance != "obs-a" {
		t.Fatalf("first path = %#v", got.Paths[0])
	}
	if got.Paths[1].finding().Finding.ID != "F-unknown" || got.Paths[1].Confident || len(got.Paths[1].Uncertainties) != 3 {
		t.Fatalf("uncertain path = %#v", got.Paths[1])
	}
	for _, p := range got.Paths {
		if p.finding().Finding.ID == "F-forbidden" {
			t.Fatalf("forbidden path present: %s", p.ID)
		}
	}
	filtered, err := g.Traverse(context.Background(), Query{Target: "db", Entrypoint: "exposure", Finding: "F-good"}, Limits{})
	if err != nil || len(filtered.Paths) != 1 || filtered.Paths[0].finding().Finding.ID != "F-good" {
		t.Fatalf("AND filters: %#v, %v", filtered, err)
	}
	importedTarget := FindingTarget{ID: "F-good", Kind: TargetImported}
	g.Findings[importedTarget] = FindingNode{Input: FindingInput{Target: importedTarget, Finding: finding.Finding{ID: "F-good", Severity: shared.SeverityHigh}, External: true}}
	g.Edges = append(g.Edges, LogicalEdge{From: "db", To: "F-good", ToTarget: TargetImported, Kind: asset.EdgeAffectedBy, Finding: true, Observed: true, Evidence: []EdgeEvidence{{Provenance: "bind-imported", Confidence: asset.EdgeObserved}}})
	legacy, err := g.Traverse(context.Background(), Query{Finding: "F-good"}, Limits{})
	if err != nil || len(legacy.Paths) != 2 {
		t.Fatalf("legacy same-id filter = %#v, %v", legacy, err)
	}
	canonicalTarget := FindingTarget{ID: "F-good", Kind: TargetCanonical}
	canonical, err := g.Traverse(context.Background(), Query{Finding: "F-good", FindingTarget: &canonicalTarget}, Limits{})
	if err != nil || len(canonical.Paths) != 1 || canonical.Paths[0].finding().Target != canonicalTarget {
		t.Fatalf("canonical same-id filter = %#v, %v", canonical, err)
	}
	imported, err := g.Traverse(context.Background(), Query{Finding: "F-good", FindingTarget: &importedTarget}, Limits{})
	if err != nil || len(imported.Paths) != 1 || imported.Paths[0].finding().Target != importedTarget {
		t.Fatalf("imported same-id filter = %#v, %v", imported, err)
	}
	if _, err := g.Traverse(context.Background(), Query{FindingTarget: &FindingTarget{ID: "F-good", Kind: "invalid"}}, Limits{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad finding target error = %v", err)
	}
	if _, err := g.Traverse(context.Background(), Query{Target: "missing"}, Limits{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad target error = %v", err)
	}
}

func TestSyntheticEstateProjection(t *testing.T) {
	var fixture struct {
		Tenant shared.ID `json:"tenant"`
		Assets []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
			Key  string `json:"key"`
			Name string `json:"name"`
		} `json:"assets"`
		Edges []struct {
			From       string `json:"from"`
			To         string `json:"to"`
			Kind       string `json:"kind"`
			Provenance string `json:"provenance"`
			Confidence string `json:"confidence"`
		} `json:"edges"`
		Findings []struct {
			ID           string  `json:"id"`
			Severity     string  `json:"severity"`
			Reachability string  `json:"reachability"`
			Tier         string  `json:"tier"`
			Provenance   string  `json:"provenance"`
			RiskScore    float64 `json:"risk_score"`
			KEV          bool    `json:"kev"`
			Confirmed    bool    `json:"confirmed"`
		} `json:"findings"`
		Bindings []struct {
			AssetID    string `json:"asset_id"`
			FindingID  string `json:"finding_id"`
			Producer   string `json:"producer"`
			Provenance string `json:"provenance"`
			Confidence string `json:"confidence"`
		} `json:"bindings"`
	}
	var expected struct {
		OrderedFindingIDs  []shared.ID                 `json:"ordered_finding_ids"`
		ExcludedFindingIDs []shared.ID                 `json:"excluded_finding_ids"`
		Uncertainties      map[shared.ID][]Uncertainty `json:"uncertainties"`
	}
	read := func(name string, dst any) {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatal(err)
		}
	}
	read("synthetic_estate.json", &fixture)
	read("synthetic_estate.expected.json", &expected)
	in := Input{TenantID: fixture.Tenant}
	for _, a := range fixture.Assets {
		in.Assets = append(in.Assets, asset.Asset{ID: shared.ID(a.ID), TenantID: fixture.Tenant, Kind: asset.Kind(a.Kind), Key: a.Key, Name: a.Name})
	}
	for _, e := range fixture.Edges {
		in.Edges = append(in.Edges, asset.Edge{TenantID: fixture.Tenant, From: shared.ID(e.From), To: shared.ID(e.To), Kind: asset.EdgeKind(e.Kind), Provenance: shared.ID(e.Provenance), Confidence: asset.EdgeConfidence(e.Confidence)})
	}
	for _, f := range fixture.Findings {
		in.Findings = append(in.Findings, FindingInput{Finding: finding.Finding{ID: shared.ID(f.ID), RiskScore: f.RiskScore, Severity: shared.Severity(f.Severity), KEV: f.KEV}, Reachability: judgment.ReachabilityState(f.Reachability), Tier: judgment.ReachabilityTier(f.Tier), Provenance: shared.ID(f.Provenance), Confirmed: f.Confirmed})
	}
	for _, b := range fixture.Bindings {
		in.Bindings = append(in.Bindings, Binding{AssetID: shared.ID(b.AssetID), FindingID: shared.ID(b.FindingID), Producer: shared.ID(b.Producer), Provenance: shared.ID(b.Provenance), Confidence: asset.EdgeConfidence(b.Confidence)})
	}
	g, err := NewGraph(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.Traverse(context.Background(), Query{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Paths) != len(expected.OrderedFindingIDs) {
		t.Fatalf("paths = %#v", got.Paths)
	}
	for i, path := range got.Paths {
		id := path.finding().Finding.ID
		if id != expected.OrderedFindingIDs[i] {
			t.Fatalf("path %d finding = %q, want %q", i, id, expected.OrderedFindingIDs[i])
		}
		if want := expected.Uncertainties[id]; !sameUncertainties(path.Uncertainties, want) {
			t.Fatalf("%s uncertainties = %#v, want %#v", id, path.Uncertainties, want)
		}
	}
	for _, forbidden := range expected.ExcludedFindingIDs {
		for _, path := range got.Paths {
			if path.finding().Finding.ID == forbidden {
				t.Fatalf("excluded finding %q returned", forbidden)
			}
		}
	}
}

func sameUncertainties(got, want []Uncertainty) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestTraverseBoundsAndCancellation(t *testing.T) {
	g := testGraph(t)
	bounded, err := g.Traverse(context.Background(), Query{}, Limits{MaxLength: 2})
	if err != nil || !bounded.Bounds.LengthHit || !bounded.Bounds.Truncated || bounded.Bounds.MaxLength != 2 || len(bounded.Paths) != 1 || len(bounded.Paths[0].Steps) != 2 {
		t.Fatalf("length bound = %#v, %v", bounded, err)
	}
	now := time.Unix(1, 0)
	calls := 0
	deadline, err := g.Traverse(context.Background(), Query{}, Limits{MaxDuration: time.Nanosecond, Now: func() time.Time { calls++; return now.Add(time.Duration(calls) * time.Nanosecond) }})
	if err != nil || !deadline.Bounds.WallClockHit || !deadline.Bounds.Truncated {
		t.Fatalf("deadline = %#v, %v", deadline, err)
	}
	g.Edges = append(g.Edges, LogicalEdge{From: "web", To: "F-good", Kind: asset.EdgeAffectedBy, Finding: true, Observed: true, Evidence: []EdgeEvidence{{Provenance: "bind-short", Confidence: asset.EdgeObserved}}})
	capped, err := g.Traverse(context.Background(), Query{}, Limits{MaxPaths: 1})
	if err != nil || !capped.Bounds.PathsHit || !capped.Bounds.Truncated || len(capped.Paths) != 2 || capped.Paths[0].finding().Finding.ID != "F-good" || len(capped.Paths[0].Steps) != 2 {
		t.Fatalf("per-finding cap = %#v, %v", capped, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Traverse(ctx, Query{}, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestTraverseCountsTerminalStepAndChecksEveryEdge(t *testing.T) {
	g := testGraph(t)
	result, err := g.Traverse(context.Background(), Query{Entrypoint: "exposure", Finding: "F-good"}, Limits{MaxLength: 2})
	if err != nil || len(result.Paths) != 0 || !result.Bounds.LengthHit {
		t.Fatalf("terminal length = %#v, %v", result, err)
	}
	calls := 0
	_, err = g.Traverse(context.Background(), Query{}, Limits{MaxDuration: 4 * time.Nanosecond, Now: func() time.Time {
		calls++
		return time.Unix(1, 0).Add(time.Duration(calls) * time.Nanosecond)
	}})
	if err != nil || calls < 5 {
		t.Fatalf("per-edge deadline checks = %d, %v", calls, err)
	}
}

func TestTraverseCapsTargetAndFindingGroups(t *testing.T) {
	g := testGraph(t)
	g.Edges = append(g.Edges, LogicalEdge{From: "web", To: "F-good", Kind: asset.EdgeAffectedBy, Finding: true, Observed: true, Evidence: []EdgeEvidence{{Provenance: "bind-short", Confidence: asset.EdgeObserved}}})
	byFinding, err := g.Traverse(context.Background(), Query{}, Limits{MaxPaths: 1})
	if err != nil || len(byFinding.Paths) != 2 || !byFinding.Bounds.FindingPathsHit || byFinding.Bounds.TargetPathsHit {
		t.Fatalf("finding cap = %#v, %v", byFinding, err)
	}
	byTarget, err := g.Traverse(context.Background(), Query{Target: "web"}, Limits{MaxPaths: 1})
	if err != nil || len(byTarget.Paths) != 1 || !byTarget.Bounds.TargetPathsHit || byTarget.Bounds.FindingPathsHit {
		t.Fatalf("target cap = %#v, %v", byTarget, err)
	}
}

func TestPathIDAndOrderAreStable(t *testing.T) {
	g := testGraph(t)
	a, err := g.Traverse(context.Background(), Query{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.Traverse(context.Background(), Query{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Paths) != len(b.Paths) {
		t.Fatal("non-deterministic result size")
	}
	for i := range a.Paths {
		if a.Paths[i].ID != b.Paths[i].ID {
			t.Fatalf("path %d IDs differ: %q != %q", i, a.Paths[i].ID, b.Paths[i].ID)
		}
	}
	if a.Paths[0].finding().Finding.ID != "F-good" {
		t.Fatalf("KEV should rank first: %#v", a.Paths)
	}
}

func TestTraverseSyntheticTenThousandAssets(t *testing.T) {
	const n = 10_000
	assets := make([]asset.Asset, n)
	edges := make([]asset.Edge, 0, n-1)
	for i := range assets {
		id := shared.ID("a" + strconv.Itoa(i))
		kind := asset.KindWorkload
		if i == 0 {
			kind = asset.KindExposure
		}
		assets[i] = testAsset(id, kind)
		if i > 0 {
			edges = append(edges, asset.Edge{TenantID: tenant, From: shared.ID("a" + strconv.Itoa(i-1)), To: id, Kind: asset.EdgeReaches, Provenance: shared.ID("p" + strconv.Itoa(i)), Confidence: asset.EdgeObserved})
		}
	}
	g, err := NewGraph(Input{TenantID: tenant, Assets: assets, Edges: edges, Findings: []FindingInput{{Finding: finding.Finding{ID: "F"}, Reachability: judgment.Reachable, Tier: judgment.Tier2, Provenance: "r", Confirmed: true}}, Bindings: []Binding{{AssetID: shared.ID("a" + strconv.Itoa(n-1)), FindingID: "F", Producer: "b", Provenance: "b", Confidence: asset.EdgeObserved}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := g.Traverse(context.Background(), Query{}, Limits{MaxLength: n + 1})
	if err != nil || len(result.Paths) != 1 || !result.Paths[0].Confident {
		t.Fatalf("synthetic result = %#v, %v", result, err)
	}
}

func BenchmarkTraverseTenThousandAssets(b *testing.B) {
	const n = 10_000
	assets := make([]asset.Asset, n)
	edges := make([]asset.Edge, 0, n-1)
	for i := range assets {
		id := shared.ID("a" + strconv.Itoa(i))
		kind := asset.KindWorkload
		if i == 0 {
			kind = asset.KindExposure
		}
		assets[i] = testAsset(id, kind)
		if i > 0 {
			edges = append(edges, asset.Edge{TenantID: tenant, From: shared.ID("a" + strconv.Itoa(i-1)), To: id, Kind: asset.EdgeReaches, Provenance: shared.ID("p" + strconv.Itoa(i)), Confidence: asset.EdgeObserved})
		}
	}
	g, err := NewGraph(Input{TenantID: tenant, Assets: assets, Edges: edges, Findings: []FindingInput{{Finding: finding.Finding{ID: "F"}, Reachability: judgment.Reachable, Tier: judgment.Tier2, Provenance: "r", Confirmed: true}}, Bindings: []Binding{{AssetID: shared.ID("a" + strconv.Itoa(n-1)), FindingID: "F", Producer: "b", Provenance: "b", Confidence: asset.EdgeObserved}}})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := g.Traverse(context.Background(), Query{}, Limits{MaxLength: n + 1}); err != nil {
			b.Fatal(err)
		}
	}
}
