package riskstoryuc

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskstory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	tenantA = shared.ID("tenant-a")
	engID   = shared.ID("eng-1")
)

// ---- fakes (narrow reader interfaces) ----

type fakeAssets struct {
	assets map[shared.ID][]*asset.Asset
	edges  map[shared.ID][]*asset.Edge
}

func (f *fakeAssets) ListAssets(_ context.Context, t shared.ID) ([]*asset.Asset, error) {
	return f.assets[t], nil
}
func (f *fakeAssets) ListEdges(_ context.Context, t shared.ID) ([]*asset.Edge, error) {
	return f.edges[t], nil
}

type fakeFindings struct {
	byEng map[shared.ID][]finding.Finding
}

func (f *fakeFindings) ListByEngagement(_ context.Context, e shared.ID) ([]finding.Finding, error) {
	return f.byEng[e], nil
}

type fakeBindings struct {
	byTenant map[shared.ID][]attackpath.Binding
}

func (f *fakeBindings) ListBindings(_ context.Context, t shared.ID) ([]attackpath.Binding, error) {
	return f.byTenant[t], nil
}

type fakeJudgments struct {
	byEng map[shared.ID][]judgment.Judgment
}

func (f *fakeJudgments) ListByEngagement(_ context.Context, e shared.ID) ([]judgment.Judgment, error) {
	return f.byEng[e], nil
}

type fakeDetections struct {
	byEng map[shared.ID][]detection.Record
}

func (f *fakeDetections) ListDetections(_ context.Context, e shared.ID) ([]detection.Record, error) {
	return f.byEng[e], nil
}

func fixedNow() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }

// fixture builds a tenant with one workload asset that has: an observed exposure edge, a reachable
// KEV finding bound to it (with a confirmed reachability judgment + occurrence/assessment refs), a
// reachability edge, and a runtime detection.
func fixture() (*fakeAssets, *fakeFindings, *fakeBindings, *fakeJudgments, *fakeDetections) {
	evalAt := fixedNow().Add(-10 * time.Minute)
	web := &asset.Asset{ID: "web", TenantID: tenantA, Kind: asset.KindWorkload, Key: "svc/web", Name: "web"}
	assets := &fakeAssets{
		assets: map[shared.ID][]*asset.Asset{tenantA: {web}},
		edges: map[shared.ID][]*asset.Edge{tenantA: {
			{TenantID: tenantA, From: "exposure", To: "web", Kind: asset.EdgeExposes, Provenance: "obs-expose", Confidence: asset.EdgeObserved},
			{TenantID: tenantA, From: "web", To: "db", Kind: asset.EdgeReaches, Provenance: "obs-reach", Confidence: asset.EdgeObserved},
		}},
	}
	findings := &fakeFindings{byEng: map[shared.ID][]finding.Finding{engID: {
		{
			ID: "F-1", EngagementID: engID, Title: "log4shell", Severity: shared.SeverityCritical,
			Priority: 1, RiskScore: 9.5, KEV: true, OccurrenceID: "occ-1", RiskAssessmentID: "assess-1",
			EvaluatedAt: &evalAt,
		},
	}}}
	bindings := &fakeBindings{byTenant: map[shared.ID][]attackpath.Binding{tenantA: {
		{TenantID: tenantA, EngagementID: engID, AssetID: "web", FindingID: "F-1", Producer: "bind", Provenance: "bind-1", Confidence: asset.EdgeObserved},
	}}}
	judgments := &fakeJudgments{byEng: map[shared.ID][]judgment.Judgment{engID: {
		{ID: "j-1", EngagementID: engID, Capability: judgment.CapReachability, SubjectID: "F-1", State: judgment.StateConfirmed, Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier2}},
	}}}
	dets := &fakeDetections{byEng: map[shared.ID][]detection.Record{engID: {
		{ID: "det-1", TenantID: tenantA, EngagementID: engID, AssetID: "web", Detection: detection.Detection{RuleID: "probe", Severity: "high", Observed: fixedNow().Add(-5 * time.Minute)}},
	}}}
	return assets, findings, bindings, judgments, dets
}

func newFixtureService(t *testing.T, staleAfter time.Duration) *Service {
	t.Helper()
	a, f, b, j, d := fixture()
	svc, err := NewService(a, f, b, j, d, staleAfter, fixedNow)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func ctxTenant(t shared.ID) context.Context {
	return shared.WithTenant(context.Background(), t)
}

func TestStoryForAssetFixtureExpectation(t *testing.T) {
	svc := newFixtureService(t, time.Hour)
	story, err := svc.StoryForAsset(ctxTenant(tenantA), engID, "web")
	if err != nil {
		t.Fatalf("StoryForAsset: %v", err)
	}

	if story.AssetID != "web" || story.TenantID != tenantA {
		t.Fatalf("scope wrong: %+v", story)
	}
	if story.Identity.Provenance != (riskstory.Provenance{Kind: riskstory.ProvAsset, ID: "web"}) {
		t.Fatalf("identity provenance wrong: %+v", story.Identity.Provenance)
	}
	if len(story.Exposure) != 1 || story.Exposure[0].Provenance.ID != "obs-expose" {
		t.Fatalf("exposure wrong: %+v", story.Exposure)
	}
	if len(story.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(story.Findings))
	}
	fe := story.Findings[0]
	if fe.FindingID != "F-1" || fe.Priority != 1 || !fe.KEV {
		t.Fatalf("finding facts wrong: %+v", fe)
	}
	if !fe.Reachable || fe.Reachability != string(judgment.Reachable) || !fe.OnAttackPath {
		t.Fatalf("corroboration wrong: %+v", fe)
	}
	if fe.Stale {
		t.Fatalf("finding should be fresh (evaluated 10m ago, target 1h)")
	}
	// Evidence must carry the attack-path binding, the reachability judgment, the occurrence and the
	// assessment — the story is navigable to every backing record.
	wantEvidence := map[string]shared.ID{
		riskstory.ProvAttackPath:   "bind-1",
		riskstory.ProvReachability: "j-1",
		riskstory.ProvOccurrence:   "occ-1",
		riskstory.ProvAssessment:   "assess-1",
	}
	got := map[string]shared.ID{}
	for _, ev := range fe.Evidence {
		got[ev.Kind] = ev.ID
	}
	if !reflect.DeepEqual(got, wantEvidence) {
		t.Fatalf("evidence refs wrong: got %+v want %+v", got, wantEvidence)
	}
	if len(story.Paths) != 1 || story.Paths[0].Provenance.ID != "obs-reach" {
		t.Fatalf("paths wrong: %+v", story.Paths)
	}
	if len(story.Detections) != 1 || story.Detections[0].Provenance.ID != "det-1" {
		t.Fatalf("detections wrong: %+v", story.Detections)
	}
	if story.Score != 1 {
		t.Fatalf("score = %d, want 1", story.Score)
	}
	if story.GeneratedAt != fixedNow() {
		t.Fatalf("generatedAt = %v, want %v", story.GeneratedAt, fixedNow())
	}
}

func TestStoriesForEngagementDeterministic(t *testing.T) {
	svc := newFixtureService(t, time.Hour)
	first, err := svc.StoriesForEngagement(ctxTenant(tenantA), engID)
	if err != nil {
		t.Fatalf("StoriesForEngagement: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("want 1 story, got %d", len(first))
	}
	for i := 0; i < 6; i++ {
		got, err := svc.StoriesForEngagement(ctxTenant(tenantA), engID)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("assembly not deterministic on run %d", i)
		}
	}
}

func TestTenantFailClosedAndIsolation(t *testing.T) {
	svc := newFixtureService(t, time.Hour)
	// No tenant in context → fail closed.
	if _, err := svc.StoriesForEngagement(context.Background(), engID); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation without tenant, got %v", err)
	}
	// A different tenant sees no assets → no stories, never the other tenant's records.
	stories, err := svc.StoriesForEngagement(ctxTenant("tenant-b"), engID)
	if err != nil {
		t.Fatalf("other tenant: %v", err)
	}
	if len(stories) != 0 {
		t.Fatalf("tenant-b should see no stories, got %d", len(stories))
	}
}

func TestUncertaintyPerClassAtAssembly(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*fakeBindings, *fakeJudgments, *fakeAssets, *fakeDetections)
		staleAf time.Duration
		wantQ   string
	}{
		{
			name: "reachability unknown",
			mutate: func(_ *fakeBindings, j *fakeJudgments, _ *fakeAssets, _ *fakeDetections) {
				j.byEng[engID][0].Claim = judgment.ReachabilityClaim{Reachable: judgment.ReachUnknown}
			},
			staleAf: time.Hour,
			wantQ:   riskstory.QualReachabilityUnknown,
		},
		{
			name: "inferred binding edge",
			mutate: func(b *fakeBindings, _ *fakeJudgments, _ *fakeAssets, _ *fakeDetections) {
				b.byTenant[tenantA][0].Confidence = asset.EdgeInferred
			},
			staleAf: time.Hour,
			wantQ:   riskstory.QualInferredEdge,
		},
		{
			name:    "stale finding",
			mutate:  func(_ *fakeBindings, _ *fakeJudgments, _ *fakeAssets, _ *fakeDetections) {},
			staleAf: time.Minute, // evaluated 10m ago > 1m target → stale
			wantQ:   riskstory.QualStale,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, f, b, j, d := fixture()
			tc.mutate(b, j, a, d)
			svc, err := NewService(a, f, b, j, d, tc.staleAf, fixedNow)
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			story, err := svc.StoryForAsset(ctxTenant(tenantA), engID, "web")
			if err != nil {
				t.Fatalf("StoryForAsset: %v", err)
			}
			found := false
			for _, q := range story.Qualifiers {
				if q == tc.wantQ {
					found = true
				}
			}
			if !found {
				t.Fatalf("qualifier %q not carried; story qualifiers=%v", tc.wantQ, story.Qualifiers)
			}
		})
	}
}

func TestBindingFromOtherEngagementExcluded(t *testing.T) {
	a, f, b, j, d := fixture()
	// Re-point the binding at a different engagement → the finding is no longer attributed here.
	b.byTenant[tenantA][0].EngagementID = "eng-other"
	svc, err := NewService(a, f, b, j, d, time.Hour, fixedNow)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	story, err := svc.StoryForAsset(ctxTenant(tenantA), engID, "web")
	if err != nil {
		t.Fatalf("StoryForAsset: %v", err)
	}
	if len(story.Findings) != 0 {
		t.Fatalf("binding from another engagement must not attribute a finding: %+v", story.Findings)
	}
}

// A strictly stronger reachability proof tier must win regardless of the order judgments arrive in —
// a later Tier-1 "unknown" must never override a Tier-2 "reachable" deterministic proof (ADR-0024).
func TestReachabilityStrongestTierWinsOrderIndependent(t *testing.T) {
	strong := judgment.Judgment{ID: "j-strong", EngagementID: engID, Capability: judgment.CapReachability, SubjectID: "F-1", State: judgment.StateConfirmed, Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier2}}
	weak := judgment.Judgment{ID: "j-weak", EngagementID: engID, Capability: judgment.CapReachability, SubjectID: "F-1", State: judgment.StateConfirmed, Claim: judgment.ReachabilityClaim{Reachable: judgment.ReachUnknown, Tier: judgment.Tier1}}

	for i, order := range [][]judgment.Judgment{{strong, weak}, {weak, strong}} {
		a, f, b, j, d := fixture()
		j.byEng[engID] = order
		svc, err := NewService(a, f, b, j, d, time.Hour, fixedNow)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		story, err := svc.StoryForAsset(ctxTenant(tenantA), engID, "web")
		if err != nil {
			t.Fatalf("StoryForAsset: %v", err)
		}
		fe := story.Findings[0]
		if fe.Reachability != string(judgment.Reachable) || !fe.Reachable {
			t.Fatalf("Tier-2 proof did not win (order case %d): reachability=%q reachable=%v", i, fe.Reachability, fe.Reachable)
		}
		// The winning judgment's id is the cited reachability evidence.
		if !hasEvidence(fe, riskstory.ProvReachability, "j-strong") {
			t.Fatalf("expected j-strong cited as reachability evidence, got %+v", fe.Evidence)
		}
	}
}

func TestSeenUnderAttackTracksFreshDetection(t *testing.T) {
	// Fresh detection (5m ago) with a 1h target → seen under attack, corroboration reason present.
	svc := newFixtureService(t, time.Hour)
	story, err := svc.StoryForAsset(ctxTenant(tenantA), engID, "web")
	if err != nil {
		t.Fatalf("StoryForAsset: %v", err)
	}
	fe := story.Findings[0]
	if !fe.SeenUnderAttack {
		t.Fatalf("finding should be seen-under-attack (fresh detection on asset)")
	}
	if !containsStr(fe.Corroboration, "seen_under_attack") {
		t.Fatalf("corroboration missing seen_under_attack: %v", fe.Corroboration)
	}

	// A stale detection (5m ago) with a 1m target → NOT current attack.
	a, f, b, j, d := fixture()
	svc2, err := NewService(a, f, b, j, d, time.Minute, fixedNow)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	story2, err := svc2.StoryForAsset(ctxTenant(tenantA), engID, "web")
	if err != nil {
		t.Fatalf("StoryForAsset: %v", err)
	}
	if story2.Findings[0].SeenUnderAttack {
		t.Fatalf("stale detection must not corroborate seen-under-attack")
	}
}

func hasEvidence(fe riskstory.FindingElement, kind string, id shared.ID) bool {
	for _, ev := range fe.Evidence {
		if ev.Kind == kind && ev.ID == id {
			return true
		}
	}
	return false
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestNewServiceRejectsNilDeps(t *testing.T) {
	if _, err := NewService(nil, nil, nil, nil, nil, time.Hour, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}
