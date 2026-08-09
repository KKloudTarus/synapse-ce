// Package attackpath derives bounded, evidence-carrying paths from estate assets to findings.
package attackpath

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type AssetNode struct {
	Asset asset.Asset `json:"asset"`
}
type FindingNode struct {
	Input FindingInput `json:"input"`
}
type Node struct {
	Asset   *AssetNode   `json:"asset,omitempty"`
	Finding *FindingNode `json:"finding,omitempty"`
}

func (n Node) ID() shared.ID {
	if n.Asset != nil {
		return n.Asset.Asset.ID
	}
	if n.Finding != nil {
		return n.Finding.Input.Target.ID
	}
	return ""
}

type TargetKind string

const (
	TargetCanonical TargetKind = "canonical"
	TargetImported  TargetKind = "imported"
)

func (k TargetKind) Valid() bool { return k == TargetCanonical || k == TargetImported }

type FindingTarget struct {
	ID   shared.ID  `json:"ID"`
	Kind TargetKind `json:"Kind"`
}

type FindingInput struct {
	Target             FindingTarget               `json:"target"`
	Finding            finding.Finding             `json:"finding"`
	Reachability       judgment.ReachabilityState  `json:"reachability"`
	Tier               judgment.ReachabilityTier   `json:"tier"`
	Provenance         shared.ID                   `json:"provenance"`
	Confirmed          bool                        `json:"confirmed"`
	External           bool                        `json:"external"`
	ImportedProvenance *importedfinding.Provenance `json:"importedProvenance,omitempty"`
}
type Binding struct {
	TenantID     shared.ID
	EngagementID shared.ID
	AssetID      shared.ID
	FindingID    shared.ID
	TargetKind   TargetKind
	Producer     shared.ID
	Provenance   shared.ID
	Confidence   asset.EdgeConfidence
}
type EdgeEvidence struct {
	Producer   shared.ID            `json:"producer"`
	Provenance shared.ID            `json:"provenance"`
	Confidence asset.EdgeConfidence `json:"confidence"`
}
type LogicalEdge struct {
	From     shared.ID      `json:"from"`
	To       shared.ID      `json:"to"`
	ToTarget TargetKind     `json:"toTargetKind,omitempty"`
	Kind     asset.EdgeKind `json:"kind"`
	Evidence []EdgeEvidence `json:"evidence"`
	Observed bool           `json:"observed"`
	Finding  bool           `json:"finding"`
}
type Input struct {
	TenantID shared.ID
	Assets   []asset.Asset
	Edges    []asset.Edge
	Bindings []Binding
	Findings []FindingInput
}
type Graph struct {
	TenantID shared.ID
	Assets   map[shared.ID]AssetNode
	Findings map[FindingTarget]FindingNode
	Edges    []LogicalEdge
}

func NewGraph(in Input) (*Graph, error) {
	if in.TenantID.IsZero() {
		return nil, validation("tenant id is required")
	}
	g := &Graph{TenantID: in.TenantID, Assets: make(map[shared.ID]AssetNode, len(in.Assets)), Findings: make(map[FindingTarget]FindingNode, len(in.Findings))}
	for _, a := range in.Assets {
		if a.ID.IsZero() || a.TenantID != in.TenantID || !a.Kind.Valid() {
			return nil, validation("asset has an invalid tenant, id, or kind")
		}
		if _, exists := g.Assets[a.ID]; exists {
			return nil, validation("duplicate asset id %q", a.ID)
		}
		g.Assets[a.ID] = AssetNode{Asset: a}
	}
	for _, f := range in.Findings {
		if f.Target.Kind == "" {
			f.Target = FindingTarget{ID: f.Finding.ID, Kind: TargetCanonical}
		}
		if f.Target.ID.IsZero() || f.Target.ID != f.Finding.ID || !f.Target.Kind.Valid() {
			return nil, validation("finding target is invalid")
		}
		if f.Target.Kind == TargetImported && (!f.External || f.ImportedProvenance == nil) {
			return nil, validation("imported finding needs external provenance")
		}
		if f.Reachability != "" && (!f.Reachability.Valid() || !f.Tier.Valid() || f.Provenance.IsZero()) {
			return nil, validation("finding reachability needs a valid state, tier, and provenance")
		}
		if f.Reachability == "" && (f.Tier != "" || !f.Provenance.IsZero() || f.Confirmed) {
			return nil, validation("missing finding reachability cannot have proof metadata")
		}
		if _, exists := g.Findings[f.Target]; exists {
			return nil, validation("duplicate finding target %q/%q", f.Target.Kind, f.Target.ID)
		}
		g.Findings[f.Target] = FindingNode{Input: f}
	}
	type key struct {
		from, to shared.ID
		target   TargetKind
		kind     asset.EdgeKind
		finding  bool
	}
	grouped := map[key][]EdgeEvidence{}
	for _, e := range in.Edges {
		if e.TenantID != in.TenantID || e.From.IsZero() || e.To.IsZero() || !e.Kind.Valid() || e.Provenance.IsZero() || !e.Confidence.Valid() {
			return nil, validation("asset edge is invalid")
		}
		if _, ok := g.Assets[e.From]; !ok {
			return nil, validation("edge source %q is not an asset", e.From)
		}
		if _, ok := g.Assets[e.To]; !ok {
			return nil, validation("edge target %q is not an asset", e.To)
		}
		grouped[key{from: e.From, to: e.To, kind: e.Kind}] = append(grouped[key{from: e.From, to: e.To, kind: e.Kind}], EdgeEvidence{Provenance: e.Provenance, Confidence: e.Confidence})
	}
	for _, b := range in.Bindings {
		if b.TargetKind == "" {
			b.TargetKind = TargetCanonical
		}
		if b.TenantID.IsZero() {
			b.TenantID = in.TenantID
		}
		target := FindingTarget{ID: b.FindingID, Kind: b.TargetKind}
		fn, ok := g.Findings[target]
		if b.EngagementID.IsZero() && ok {
			b.EngagementID = fn.Input.Finding.EngagementID
		}
		if b.TenantID != in.TenantID || b.AssetID.IsZero() || b.FindingID.IsZero() || !b.TargetKind.Valid() || b.Producer.IsZero() || b.Provenance.IsZero() || !b.Confidence.Valid() {
			return nil, validation("binding is invalid")
		}
		if _, ok := g.Assets[b.AssetID]; !ok {
			return nil, validation("binding asset %q is not an asset", b.AssetID)
		}
		if !ok {
			return nil, validation("binding finding %q/%q is not a finding", b.TargetKind, b.FindingID)
		}
		if !b.EngagementID.IsZero() && fn.Input.Finding.EngagementID != b.EngagementID {
			return nil, validation("binding finding %q belongs to another engagement", b.FindingID)
		}
		k := key{from: b.AssetID, to: b.FindingID, target: b.TargetKind, kind: asset.EdgeAffectedBy, finding: true}
		grouped[k] = append(grouped[k], EdgeEvidence{Producer: b.Producer, Provenance: b.Provenance, Confidence: b.Confidence})
	}
	for k, evidence := range grouped {
		sort.Slice(evidence, func(i, j int) bool {
			if evidence[i].Producer != evidence[j].Producer {
				return evidence[i].Producer < evidence[j].Producer
			}
			if evidence[i].Provenance != evidence[j].Provenance {
				return evidence[i].Provenance < evidence[j].Provenance
			}
			return evidence[i].Confidence < evidence[j].Confidence
		})
		observed := false
		for _, e := range evidence {
			observed = observed || e.Confidence == asset.EdgeObserved
		}
		g.Edges = append(g.Edges, LogicalEdge{From: k.from, To: k.to, ToTarget: k.target, Kind: k.kind, Evidence: evidence, Observed: observed, Finding: k.finding})
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.ToTarget != b.ToTarget {
			return a.ToTarget < b.ToTarget
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return !a.Finding && b.Finding
	})
	return g, nil
}
func validation(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{shared.ErrValidation}, args...)...)
}
