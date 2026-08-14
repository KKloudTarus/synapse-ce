package riskstory

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func baseInputs() Inputs {
	return Inputs{
		AssetID:  "asset-1",
		TenantID: "tenant-1",
		Identity: AssetFacts{Kind: "exposure", Key: "svc/api", Name: "api", Provenance: Provenance{Kind: ProvAsset, ID: "asset-1"}},
		Findings: []FindingElement{
			{FindingID: "f-1", Title: "sqli", Severity: "high", Priority: 2, RiskScore: 8.1, Provenance: Provenance{Kind: ProvFinding, ID: "f-1"}},
		},
		GeneratedAt: time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC),
	}
}

func TestAssembleRejectsElementWithoutBackingRecord(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Inputs)
	}{
		{"missing asset scope", func(in *Inputs) { in.AssetID = "" }},
		{"identity not asset-backed", func(in *Inputs) { in.Identity.Provenance = Provenance{} }},
		{"finding no provenance", func(in *Inputs) { in.Findings[0].Provenance = Provenance{} }},
		{"finding bad provenance kind", func(in *Inputs) { in.Findings[0].Provenance = Provenance{Kind: "guess", ID: "f-1"} }},
		{"finding evidence no id", func(in *Inputs) {
			in.Findings[0].Evidence = []Provenance{{Kind: ProvReachability, ID: ""}}
		}},
		{"exposure no provenance", func(in *Inputs) {
			in.Exposure = []ExposureElement{{Description: "public", Confidence: "observed"}}
		}},
		{"path no provenance", func(in *Inputs) {
			in.Paths = []PathElement{{Summary: "ingress→db", Confidence: "inferred"}}
		}},
		{"detection no provenance", func(in *Inputs) {
			in.Detections = []DetectionElement{{RuleID: "r1", Severity: "high"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInputs()
			tc.mutate(&in)
			if _, err := Assemble(in); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestAssembleValidStoryPasses(t *testing.T) {
	s, err := Assemble(baseInputs())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Score != 2 {
		t.Fatalf("score = %d, want 2 (worst finding priority)", s.Score)
	}
	if s.GeneratedAt.Location() != time.UTC {
		t.Fatalf("GeneratedAt not normalized to UTC")
	}
}

// Each uncertainty class must survive assembly on its element and roll up to the story.
func TestUncertaintyCarriedPerClass(t *testing.T) {
	tests := []struct {
		name string
		in   func() Inputs
		qual string
	}{
		{"reachability unknown", func() Inputs {
			in := baseInputs()
			in.Findings[0].Reachability = "unknown"
			in.Findings[0].Qualifiers = []string{QualReachabilityUnknown}
			return in
		}, QualReachabilityUnknown},
		{"inferred edge", func() Inputs {
			in := baseInputs()
			in.Exposure = []ExposureElement{{Description: "guessed", Confidence: "inferred", Provenance: Provenance{Kind: ProvAssetEdge, ID: "e-1"}, Qualifiers: []string{QualInferredEdge}}}
			return in
		}, QualInferredEdge},
		{"sampled telemetry window", func() Inputs {
			in := baseInputs()
			in.Detections = []DetectionElement{{RuleID: "r1", Severity: "high", Observed: time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC), Provenance: Provenance{Kind: ProvDetection, ID: "d-1"}, Qualifiers: []string{QualSampledWindow}}}
			return in
		}, QualSampledWindow},
		{"stale", func() Inputs {
			in := baseInputs()
			in.Findings[0].Stale = true
			in.Findings[0].Qualifiers = []string{QualStale}
			return in
		}, QualStale},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Assemble(tc.in())
			if err != nil {
				t.Fatalf("assemble: %v", err)
			}
			if !contains(s.Qualifiers, tc.qual) {
				t.Fatalf("story qualifiers %v missing %q", s.Qualifiers, tc.qual)
			}
		})
	}
}

// Equal-priority findings: the one with more corroborating signals must rank first, and RankReason
// must explain why — priority itself is never mutated.
func TestCorroborationRaisesOrderingNotPriority(t *testing.T) {
	in := baseInputs()
	in.Findings = []FindingElement{
		{FindingID: "plain", Priority: 3, RiskScore: 5, Provenance: Provenance{Kind: ProvFinding, ID: "plain"}},
		{FindingID: "corrob", Priority: 3, RiskScore: 5, Reachable: true, OnAttackPath: true, SeenUnderAttack: true, Provenance: Provenance{Kind: ProvFinding, ID: "corrob"}},
	}
	s, err := Assemble(in)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if s.Findings[0].FindingID != "corrob" {
		t.Fatalf("corroborated finding did not rank first: order=%v", ids(s.Findings))
	}
	if s.Findings[0].Priority != 3 || s.Findings[1].Priority != 3 {
		t.Fatalf("priority mutated by corroboration: %d,%d", s.Findings[0].Priority, s.Findings[1].Priority)
	}
	if s.Findings[0].RankReason == "" || s.Findings[1].RankReason == "" {
		t.Fatalf("rank reason missing")
	}
	if want := "raised by corroboration: reachable + on_attack_path + seen_under_attack"; s.Findings[0].RankReason != want {
		t.Fatalf("rank reason = %q, want %q", s.Findings[0].RankReason, want)
	}
}

// Lower priority number always outranks corroboration on a higher number — corroboration only breaks
// ties within the same priority.
func TestPriorityDominatesCorroboration(t *testing.T) {
	in := baseInputs()
	in.Findings = []FindingElement{
		{FindingID: "p4-corrob", Priority: 4, Reachable: true, OnAttackPath: true, SeenUnderAttack: true, Provenance: Provenance{Kind: ProvFinding, ID: "p4-corrob"}},
		{FindingID: "p1-plain", Priority: 1, Provenance: Provenance{Kind: ProvFinding, ID: "p1-plain"}},
	}
	s, err := Assemble(in)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if s.Findings[0].FindingID != "p1-plain" {
		t.Fatalf("priority-1 finding did not rank first: %v", ids(s.Findings))
	}
	if s.Score != 1 {
		t.Fatalf("score = %d, want 1", s.Score)
	}
}

func TestAssemblyIsDeterministic(t *testing.T) {
	build := func() Story {
		in := baseInputs()
		in.Findings = []FindingElement{
			{FindingID: "b", Priority: 2, RiskScore: 3, Provenance: Provenance{Kind: ProvFinding, ID: "b"}},
			{FindingID: "a", Priority: 2, RiskScore: 3, Provenance: Provenance{Kind: ProvFinding, ID: "a"}},
			{FindingID: "c", Priority: 1, RiskScore: 9, Provenance: Provenance{Kind: ProvFinding, ID: "c"}},
		}
		in.Exposure = []ExposureElement{
			{Description: "y", Confidence: "observed", Provenance: Provenance{Kind: ProvAssetEdge, ID: "e-y"}},
			{Description: "x", Confidence: "observed", Provenance: Provenance{Kind: ProvAssetEdge, ID: "e-x"}},
		}
		s, err := Assemble(in)
		if err != nil {
			t.Fatalf("assemble: %v", err)
		}
		return s
	}
	first := build()
	for i := 0; i < 8; i++ {
		if got := build(); !reflect.DeepEqual(first, got) {
			t.Fatalf("assembly not deterministic on run %d", i)
		}
	}
	// Tie on (priority, corroboration, riskScore) breaks by id ascending.
	if ids(first.Findings)[0] != "c" || ids(first.Findings)[1] != "a" || ids(first.Findings)[2] != "b" {
		t.Fatalf("tie-break order wrong: %v", ids(first.Findings))
	}
}

func TestFresh(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		last   time.Time
		target time.Duration
		want   bool
	}{
		{"zero never fresh", time.Time{}, time.Hour, false},
		{"no target is fresh once observed", now.Add(-1000 * time.Hour), 0, true},
		{"within target", now.Add(-30 * time.Minute), time.Hour, true},
		{"beyond target", now.Add(-2 * time.Hour), time.Hour, false},
		{"exactly at target", now.Add(-time.Hour), time.Hour, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Fresh(tc.last, now, tc.target); got != tc.want {
				t.Fatalf("Fresh = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvidenceRefsCarriesEveryBackingRecord(t *testing.T) {
	in := baseInputs()
	in.Findings[0].Evidence = []Provenance{
		{Kind: ProvReachability, ID: "reach-1"},
		{Kind: ProvOccurrence, ID: "occ-1"},
		{Kind: ProvReachability, ID: "reach-1"}, // dup, must collapse
	}
	in.Exposure = []ExposureElement{{Description: "x", Confidence: "observed", Provenance: Provenance{Kind: ProvAssetEdge, ID: "e-1"}}}
	in.Detections = []DetectionElement{{RuleID: "r", Severity: "high", Provenance: Provenance{Kind: ProvDetection, ID: "d-1"}}}
	s, err := Assemble(in)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	refs := s.EvidenceRefs()
	want := []Provenance{
		{Kind: ProvAsset, ID: "asset-1"},
		{Kind: ProvAssetEdge, ID: "e-1"},
		{Kind: ProvDetection, ID: "d-1"},
		{Kind: ProvFinding, ID: "f-1"},
		{Kind: ProvOccurrence, ID: "occ-1"},
		{Kind: ProvReachability, ID: "reach-1"},
	}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("evidence refs = %+v, want %+v", refs, want)
	}
	// Deterministic across repeated calls.
	if !reflect.DeepEqual(refs, s.EvidenceRefs()) {
		t.Fatalf("EvidenceRefs not deterministic")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func ids(fs []FindingElement) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = string(f.FindingID)
	}
	return out
}
