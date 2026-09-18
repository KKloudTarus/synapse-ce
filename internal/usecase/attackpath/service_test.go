package attackpath

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	ap "github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

type noJudgments struct{}

func (noJudgments) Save(context.Context, judgment.Judgment) error { return nil }
func (noJudgments) ListByEngagement(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return nil, nil
}
func (noJudgments) ListBySubject(context.Context, shared.ID, shared.ID) ([]judgment.Judgment, error) {
	return nil, nil
}

func TestServiceTenantScopedQuery(t *testing.T) {
	ctx := context.Background()
	assets := memory.NewAssetStore()
	bindings := memory.NewAttackPathStore()
	findings := memory.NewFindingRepository()
	imported := memory.NewImportedFindingStore()
	engagements := memory.NewEngagementRepository()
	now := time.Unix(1, 0).UTC()
	for _, a := range []*asset.Asset{
		{ID: "ex", TenantID: "ta", Kind: asset.KindExposure, Key: "ex", Name: "ex"},
		{ID: "app", TenantID: "ta", Kind: asset.KindWorkload, Key: "app", Name: "app"},
	} {
		if err := assets.UpsertAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	edge, _ := asset.NewEdge("ta", "ex", "app", asset.EdgeExposes, "obs", asset.EdgeObserved)
	if err := assets.UpsertEdge(ctx, edge); err != nil {
		t.Fatal(err)
	}
	eng, _ := engagement.New("eng", "ta", "eng", "client", now)
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	f, _ := finding.NewManual("f", "eng", finding.ManualInput{Title: "issue", Severity: shared.SeverityHigh}, now)
	if err := findings.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ReplaceBindings(ctx, "ta", "eng", "finding:f", []ap.Binding{{TenantID: "ta", EngagementID: "eng", AssetID: "app", FindingID: "f", Producer: "finding:f", Provenance: "finding:f", Confidence: asset.EdgeObserved}}); err != nil {
		t.Fatal(err)
	}

	svc, err := NewService(assets, bindings, findings, imported, noJudgments{}, engagements, ap.Limits{MaxLength: 12, MaxPaths: 100, MaxDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Query(ctx, "ta", ap.Query{Target: "app", Finding: "f"})
	if err != nil || len(got.Paths) != 1 || got.Paths[0].Confident {
		t.Fatalf("tenant path = %#v, %v", got, err)
	}
	other, err := svc.Query(ctx, "tb", ap.Query{Finding: "f"})
	if err != nil || len(other.Paths) != 0 || other.Paths == nil {
		t.Fatalf("cross-tenant query = %#v, %v", other, err)
	}
	missing, err := svc.Query(ctx, "ta", ap.Query{Target: "other-tenant", Finding: "f"})
	if err != nil || len(missing.Paths) != 0 || missing.Paths == nil || missing.Bounds.MaxLength != 12 {
		t.Fatalf("hidden filter query = %#v, %v", missing, err)
	}
}

func TestVisibleQueryMatchesTypedFindingTarget(t *testing.T) {
	canonical := ap.FindingTarget{ID: "same", Kind: ap.TargetCanonical}
	imported := ap.FindingTarget{ID: "same", Kind: ap.TargetImported}
	graph := &ap.Graph{Findings: map[ap.FindingTarget]ap.FindingNode{canonical: {}, imported: {}}}
	if !visibleQuery(graph, ap.Query{Finding: "same"}) {
		t.Fatal("legacy raw finding query should match both target kinds")
	}
	if !visibleQuery(graph, ap.Query{Finding: "same", FindingTarget: &canonical}) {
		t.Fatal("canonical target should be visible")
	}
	if !visibleQuery(graph, ap.Query{Finding: "same", FindingTarget: &imported}) {
		t.Fatal("imported target should be visible")
	}
	missing := ap.FindingTarget{ID: "same", Kind: ap.TargetKind("other")}
	if visibleQuery(graph, ap.Query{Finding: "same", FindingTarget: &missing}) {
		t.Fatal("nonexistent typed target should not be visible")
	}
}

func TestServicePropagatesInvalidGraph(t *testing.T) {
	ctx := context.Background()
	assets := memory.NewAssetStore()
	bindings := memory.NewAttackPathStore()
	findings := memory.NewFindingRepository()
	imported := memory.NewImportedFindingStore()
	engagements := memory.NewEngagementRepository()
	if err := assets.UpsertAsset(ctx, &asset.Asset{ID: "app", TenantID: "ta", Kind: asset.KindExposure, Key: "app", Name: "app"}); err != nil {
		t.Fatal(err)
	}
	if err := assets.UpsertEdge(ctx, &asset.Edge{TenantID: "ta", From: "app", To: "missing", Kind: asset.EdgeExposes, Provenance: "obs", Confidence: asset.EdgeObserved}); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(assets, bindings, findings, imported, noJudgments{}, engagements, ap.Limits{MaxLength: 12, MaxPaths: 100, MaxDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Query(ctx, "ta", ap.Query{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid graph error = %v", err)
	}
}

func TestReachabilityInputUsesStrongestConfirmedProof(t *testing.T) {
	f := finding.Finding{ID: "finding", EngagementID: "eng"}
	got := reachabilityInput(f, []judgment.Judgment{
		{ID: "tier-1", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier1, Confidence: 80}, State: judgment.StateConfirmed, EvidenceScore: 75},
		{ID: "tier-2", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier2, Confidence: 95}, State: judgment.StateConfirmed, EvidenceScore: 90},
	})
	if got.Tier != judgment.Tier2 || got.Provenance != "tier-2" || !got.Confirmed || got.Reachability != judgment.Reachable {
		t.Fatalf("strongest reachability = %#v", got)
	}
}

func TestReachabilityInputPrefersPublishableProof(t *testing.T) {
	f := finding.Finding{ID: "finding", EngagementID: "eng"}
	got := reachabilityInput(f, []judgment.Judgment{
		{ID: "proposed-no", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2}, State: judgment.StateProposed},
		{ID: "confirmed-yes", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier1}, State: judgment.StateConfirmed, EvidenceScore: 75},
	})
	if got.Reachability != judgment.Reachable || got.Provenance != "confirmed-yes" || !got.Confirmed {
		t.Fatalf("publishable reachability = %#v", got)
	}
	uncertain := reachabilityInput(f, []judgment.Judgment{{ID: "refuted-no", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2}, State: judgment.StateRefuted}})
	if uncertain.Reachability != judgment.ReachUnknown || uncertain.Confirmed || uncertain.Provenance != "refuted-no" {
		t.Fatalf("unpublishable reachability = %#v", uncertain)
	}
}

// TestReachabilityInputStateAwareWithinTier: a same-tier stale not_reachable must never shadow a proven
// reachable (EPIC #1042, 0.4). Before the state-aware fix, selection broke ties on judgment id, so a
// not_reachable with a lower id could win and traverse.go would then drop the finding from every path.
func TestReachabilityInputStateAwareWithinTier(t *testing.T) {
	f := finding.Finding{ID: "finding", EngagementID: "eng"}
	// "a-not-reach" sorts before "b-reach": the old id tie-break would have picked the not_reachable.
	got := reachabilityInput(f, []judgment.Judgment{
		{ID: "a-not-reach", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2, EntrypointsPresent: true}, State: judgment.StateConfirmed, EvidenceScore: 90},
		{ID: "b-reach", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier2}, State: judgment.StateConfirmed, EvidenceScore: 90},
	})
	if got.Reachability != judgment.Reachable || got.Provenance != "b-reach" {
		t.Fatalf("same-tier reachable must win over not_reachable, got %#v", got)
	}
}

// TestReachabilityInputProofGatesNegative: an unproven not_reachable (a Tier-2 call-graph negative with no
// entry points) is not a sound basis to drop a finding from attack paths; it downgrades to unknown so
// traverse.go keeps the finding. A proven negative (entry points recorded) stays not_reachable.
func TestReachabilityInputProofGatesNegative(t *testing.T) {
	f := finding.Finding{ID: "finding", EngagementID: "eng"}
	unproven := reachabilityInput(f, []judgment.Judgment{
		{ID: "zero-entry", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2}, State: judgment.StateConfirmed, EvidenceScore: 90},
	})
	if unproven.Reachability != judgment.ReachUnknown {
		t.Fatalf("zero-entrypoint Tier-2 not_reachable must downgrade to unknown, got %#v", unproven)
	}
	proven := reachabilityInput(f, []judgment.Judgment{
		{ID: "with-entry", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2, EntrypointsPresent: true}, State: judgment.StateConfirmed, EvidenceScore: 90},
	})
	if proven.Reachability != judgment.NotReachable {
		t.Fatalf("proven Tier-2 not_reachable must stay not_reachable, got %#v", proven)
	}
}

// TestReachabilityInputUnprovenNegativeNeverShadowsReachable: a higher-tier UNPROVEN negative
// (zero-entrypoint Tier-2) must not shadow a lower-tier reachable, or the finding would lose its reachable
// score boost in the attack-path graph (EPIC #1042, 0.6). The reachable must win selection.
func TestReachabilityInputUnprovenNegativeNeverShadowsReachable(t *testing.T) {
	f := finding.Finding{ID: "finding", EngagementID: "eng"}
	got := reachabilityInput(f, []judgment.Judgment{
		{ID: "hi-tier-neg", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2}, State: judgment.StateConfirmed, EvidenceScore: 90},
		{ID: "lo-tier-reach", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "finding", Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier1}, State: judgment.StateConfirmed, EvidenceScore: 90},
	})
	if got.Reachability != judgment.Reachable || got.Provenance != "lo-tier-reach" {
		t.Fatalf("a lower-tier reachable must win over a higher-tier unproven negative, got %#v", got)
	}
}

func TestServiceIncludesBoundImportedFinding(t *testing.T) {
	ctx := context.Background()
	assets := memory.NewAssetStore()
	bindings := memory.NewAttackPathStore()
	findings := memory.NewFindingRepository()
	imported := memory.NewImportedFindingStore()
	engagements := memory.NewEngagementRepository()
	now := time.Unix(1, 0).UTC()
	if err := assets.UpsertAsset(ctx, &asset.Asset{ID: "app", TenantID: "ta", Kind: asset.KindExposure, Key: "app", Name: "app"}); err != nil {
		t.Fatal(err)
	}
	eng, _ := engagement.New("eng", "ta", "eng", "client", now)
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	external := importedfinding.ImportedFinding{ID: "external", TenantID: "ta", EngagementID: "eng", Severity: shared.SeverityHigh, Title: "external", Provenance: importedfinding.Provenance{ToolName: "tool", ToolVersion: "1", RuleID: "rule", SourceDigest: "digest", IngestedBy: "human:alice", IngestedAt: now}}
	if _, _, err := imported.Save(ctx, "ta", []importedfinding.ImportedFinding{external}); err != nil {
		t.Fatal(err)
	}
	if err := bindings.ReplaceBindings(ctx, "ta", "eng", "digest", []ap.Binding{{TenantID: "ta", EngagementID: "eng", AssetID: "app", FindingID: "external", TargetKind: ap.TargetImported, Producer: "digest", Provenance: "digest", Confidence: asset.EdgeObserved}}); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(assets, bindings, findings, imported, noJudgments{}, engagements, ap.Limits{MaxLength: 12, MaxPaths: 100, MaxDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Query(ctx, "ta", ap.Query{Target: "app", Finding: "external"})
	if err != nil || len(got.Paths) != 1 {
		t.Fatalf("imported path = %#v, %v", got, err)
	}
}

func TestServiceExcludesUnpromotableCanonicalFindings(t *testing.T) {
	tests := []struct {
		name     string
		finding  finding.Finding
		wantPath bool
	}{
		{
			name:     "low-evidence exploitation",
			finding:  finding.Finding{ID: "low-evidence", EngagementID: "eng", Title: "low evidence", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindExploitation, EvidenceScore: finding.EvidenceThreshold - 1},
			wantPath: false,
		},
		{
			name:     "agent-proposed finding",
			finding:  finding.Finding{ID: "agent-proposed", EngagementID: "eng", Title: "agent proposed", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindSAST, RuleKey: "rule", ProposedBy: "agent:scanner"},
			wantPath: false,
		},
		{
			name:     "ordinary manual finding",
			finding:  finding.Finding{ID: "manual", EngagementID: "eng", Title: "manual", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindManual},
			wantPath: true,
		},
		{
			name:     "evidence-promoted exploitation",
			finding:  finding.Finding{ID: "promoted", EngagementID: "eng", Title: "promoted", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindExploitation, EvidenceScore: finding.EvidenceThreshold},
			wantPath: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			assets := memory.NewAssetStore()
			bindings := memory.NewAttackPathStore()
			findings := memory.NewFindingRepository()
			imported := memory.NewImportedFindingStore()
			judgments := memory.NewJudgmentStore()
			engagements := memory.NewEngagementRepository()
			if err := assets.UpsertAsset(ctx, &asset.Asset{ID: "app", TenantID: "ta", Kind: asset.KindExposure, Key: "app", Name: "app"}); err != nil {
				t.Fatal(err)
			}
			eng, err := engagement.New("eng", "ta", "eng", "client", time.Unix(1, 0).UTC())
			if err != nil {
				t.Fatal(err)
			}
			if err := engagements.Create(ctx, eng); err != nil {
				t.Fatal(err)
			}
			if err := findings.Upsert(ctx, []finding.Finding{tc.finding}); err != nil {
				t.Fatal(err)
			}
			if err := judgments.Save(ctx, judgment.Judgment{ID: "reachable", EngagementID: "eng", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: tc.finding.ID, Claim: judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier1}, State: judgment.StateConfirmed, EvidenceScore: finding.EvidenceThreshold}); err != nil {
				t.Fatal(err)
			}
			if err := bindings.ReplaceBindings(ctx, "ta", "eng", shared.ID("finding:"+tc.finding.ID.String()), []ap.Binding{{TenantID: "ta", EngagementID: "eng", AssetID: "app", FindingID: tc.finding.ID, Producer: shared.ID("finding:" + tc.finding.ID.String()), Provenance: shared.ID("finding:" + tc.finding.ID.String()), Confidence: asset.EdgeObserved}}); err != nil {
				t.Fatal(err)
			}
			svc, err := NewService(assets, bindings, findings, imported, judgments, engagements, ap.Limits{MaxLength: 12, MaxPaths: 100, MaxDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			got, err := svc.Query(ctx, "ta", ap.Query{Target: "app", Finding: tc.finding.ID})
			if err != nil {
				t.Fatal(err)
			}
			if (len(got.Paths) == 1) != tc.wantPath {
				t.Fatalf("paths = %#v, want path %v", got.Paths, tc.wantPath)
			}
		})
	}
}
