// Package attackpath assembles tenant-scoped attack paths from existing records.
package attackpath

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	ap "github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service computes paths on demand; it never persists or executes a path.
type Service struct {
	assets      ports.AssetRepository
	bindings    ports.AttackPathStore
	findings    ports.FindingRepository
	imported    ports.ImportedFindingStore
	judgments   ports.JudgmentStore
	engagements ports.EngagementRepository
	limits      ap.Limits
}

func NewService(assets ports.AssetRepository, bindings ports.AttackPathStore, findings ports.FindingRepository, imported ports.ImportedFindingStore, judgments ports.JudgmentStore, engagements ports.EngagementRepository, limits ap.Limits) (*Service, error) {
	if assets == nil || bindings == nil || findings == nil || imported == nil || engagements == nil {
		return nil, fmt.Errorf("%w: attack path service needs assets, bindings, findings, imported findings, and engagements", shared.ErrValidation)
	}
	if limits.MaxLength <= 0 || limits.MaxPaths <= 0 || limits.MaxDuration <= 0 {
		return nil, fmt.Errorf("%w: attack path limits must be positive", shared.ErrValidation)
	}
	return &Service{assets: assets, bindings: bindings, findings: findings, imported: imported, judgments: judgments, engagements: engagements, limits: limits}, nil
}

func (s *Service) Query(ctx context.Context, tenantID shared.ID, query ap.Query) (ap.Result, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	assets, err := s.assets.ListAssets(ctx, tenantID)
	if err != nil {
		return ap.Result{}, fmt.Errorf("list attack path assets: %w", err)
	}
	edges, err := s.assets.ListEdges(ctx, tenantID)
	if err != nil {
		return ap.Result{}, fmt.Errorf("list attack path edges: %w", err)
	}
	bindings, err := s.bindings.ListBindings(ctx, tenantID)
	if err != nil {
		return ap.Result{}, fmt.Errorf("list attack path bindings: %w", err)
	}

	byEngagement := map[shared.ID][]ap.Binding{}
	for _, b := range bindings {
		byEngagement[b.EngagementID] = append(byEngagement[b.EngagementID], b)
	}
	engagementIDs := make([]shared.ID, 0, len(byEngagement))
	for id := range byEngagement {
		engagementIDs = append(engagementIDs, id)
	}
	sort.Slice(engagementIDs, func(i, j int) bool { return engagementIDs[i] < engagementIDs[j] })

	var findingInputs []ap.FindingInput
	var visibleBindings []ap.Binding
	for _, engagementID := range engagementIDs {
		eng, err := s.engagements.GetByIDInTenant(ctx, tenantIDForEngagement(tenantID), engagementID)
		if errors.Is(err, shared.ErrNotFound) {
			continue
		}
		if err != nil {
			return ap.Result{}, fmt.Errorf("load attack path engagement: %w", err)
		}
		if shared.TenantOrDefault(eng.TenantID) != tenantID {
			continue
		}
		findings, err := s.findings.ListByEngagement(ctx, engagementID)
		if err != nil {
			return ap.Result{}, fmt.Errorf("list attack path findings: %w", err)
		}
		imported, err := s.imported.ListByEngagement(ctx, tenantID, engagementID)
		if err != nil {
			return ap.Result{}, fmt.Errorf("list imported attack path findings: %w", err)
		}
		canonical := make(map[shared.ID]finding.Finding, len(findings))
		for _, f := range findings {
			if f.Status != finding.StatusFalsePos && f.Status != finding.StatusRemediated && f.CanPromote() {
				canonical[f.ID] = f
			}
		}
		external := make(map[shared.ID]importedfinding.ImportedFinding, len(imported))
		for _, f := range imported {
			external[f.ID] = f
		}
		judgments := []judgment.Judgment(nil)
		if s.judgments != nil {
			judgments, err = s.judgments.ListByEngagement(ctx, engagementID)
			if err != nil {
				return ap.Result{}, fmt.Errorf("list attack path judgments: %w", err)
			}
		}
		for _, b := range byEngagement[engagementID] {
			if b.TargetKind == "" {
				b.TargetKind = ap.TargetCanonical
			}
			var input ap.FindingInput
			switch b.TargetKind {
			case ap.TargetCanonical:
				f, ok := canonical[b.FindingID]
				if !ok {
					continue
				}
				input = reachabilityInput(f, judgments)
			case ap.TargetImported:
				f, ok := external[b.FindingID]
				if !ok {
					continue
				}
				input = importedFindingInput(f)
			default:
				continue
			}
			findingInputs = append(findingInputs, input)
			visibleBindings = append(visibleBindings, b)
		}
	}

	assetValues := make([]asset.Asset, len(assets))
	for i, a := range assets {
		assetValues[i] = *a
	}
	edgeValues := make([]asset.Edge, len(edges))
	for i, e := range edges {
		edgeValues[i] = *e
	}
	graph, err := ap.NewGraph(ap.Input{TenantID: tenantID, Assets: assetValues, Edges: edgeValues, Bindings: visibleBindings, Findings: dedupFindingInputs(findingInputs)})
	if err != nil {
		return ap.Result{}, fmt.Errorf("build attack path graph: %w", err)
	}
	if !visibleQuery(graph, query) {
		return ap.Result{Paths: []ap.Path{}, Bounds: configuredBounds(s.limits)}, nil
	}
	return graph.Traverse(ctx, query, s.limits)
}

// visibleQuery makes absent or cross-tenant filters indistinguishable without hiding graph errors.
func visibleQuery(graph *ap.Graph, query ap.Query) bool {
	if query.Target != "" {
		if _, ok := graph.Assets[query.Target]; !ok {
			return false
		}
	}
	if query.Entrypoint != "" {
		if _, ok := graph.Assets[query.Entrypoint]; !ok {
			return false
		}
	}
	if query.FindingTarget != nil {
		if _, ok := graph.Findings[*query.FindingTarget]; !ok {
			return false
		}
	}
	if query.Finding != "" {
		for target := range graph.Findings {
			if target.ID == query.Finding {
				return true
			}
		}
		return false
	}
	return true
}

func tenantIDForEngagement(tenantID shared.ID) shared.ID {
	if tenantID == shared.DefaultTenant {
		return ""
	}
	return tenantID
}

func reachabilityInput(f finding.Finding, judgments []judgment.Judgment) ap.FindingInput {
	best := ap.FindingInput{Target: ap.FindingTarget{ID: f.ID, Kind: ap.TargetCanonical}, Finding: f}
	bestPublishable := false
	for _, j := range judgments {
		if j.Capability != judgment.CapReachability || j.SubjectKind != judgment.SubjectFinding || j.SubjectID != f.ID {
			continue
		}
		claim, ok := j.Claim.(judgment.ReachabilityClaim)
		if !ok {
			continue
		}
		publishable := j.Publishable()
		if best.Provenance != "" && (publishable != bestPublishable && !publishable || publishable == bestPublishable && (claim.Tier.Rank() < best.Tier.Rank() || claim.Tier == best.Tier && j.ID > best.Provenance)) {
			continue
		}
		best.Reachability, best.Tier, best.Provenance, best.Confirmed = claim.Reachable, claim.Tier, j.ID, publishable
		bestPublishable = publishable
	}
	if best.Provenance != "" && !bestPublishable {
		best.Reachability = judgment.ReachUnknown
	}
	return best
}

func dedupFindingInputs(in []ap.FindingInput) []ap.FindingInput {
	seen := map[ap.FindingTarget]bool{}
	out := make([]ap.FindingInput, 0, len(in))
	for _, f := range in {
		if !seen[f.Target] {
			seen[f.Target] = true
			out = append(out, f)
		}
	}
	return out
}

func configuredBounds(limits ap.Limits) ap.BoundReport {
	return ap.BoundReport{MaxLength: limits.MaxLength, MaxPaths: limits.MaxPaths, MaxDuration: limits.MaxDuration}
}

func importedFindingInput(f importedfinding.ImportedFinding) ap.FindingInput {
	provenance := f.Provenance
	return ap.FindingInput{
		Target:             ap.FindingTarget{ID: f.ID, Kind: ap.TargetImported},
		Finding:            finding.Finding{ID: f.ID, EngagementID: f.EngagementID, Title: f.Title, Description: f.Message, Severity: f.Severity, SourceLocation: importedLocation(f)},
		External:           f.External(),
		ImportedProvenance: &provenance,
	}
}

func importedLocation(f importedfinding.ImportedFinding) *finding.SourceLocation {
	if f.Location.Path == "" || f.Location.StartLine == 0 {
		return nil
	}
	return &finding.SourceLocation{File: f.Location.Path, StartLine: f.Location.StartLine, EndLine: f.Location.StartLine}
}
