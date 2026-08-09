package attackpath

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Uncertainty identifies a fact preventing a path from being confident.
type Uncertainty string

const (
	UncertaintyInferredEdge            Uncertainty = "inferred_edge"
	UncertaintyMissingReachability     Uncertainty = "missing_reachability"
	UncertaintyUnknownReachability     Uncertainty = "unknown_reachability"
	UncertaintyUnconfirmedReachability Uncertainty = "unconfirmed_reachability"
)

// Path is a root-to-finding traversal result.
type Path struct {
	ID            string        `json:"id"`
	Nodes         []Node        `json:"nodes"`
	Steps         []Step        `json:"steps"`
	Edges         []LogicalEdge `json:"edges"`
	Uncertainties []Uncertainty `json:"uncertainties"`
	Confident     bool          `json:"confident"`
}

// Step is one ordered, evidence-carrying transition in a path.
type Step struct {
	From      shared.ID      `json:"from"`
	To        shared.ID      `json:"to"`
	ToTarget  TargetKind     `json:"toTargetKind,omitempty"`
	Kind      string         `json:"kind"`
	Evidence  []EdgeEvidence `json:"evidence"`
	Observed  bool           `json:"observed"`
	ToFinding bool           `json:"toFinding"`
}

func steps(edges []LogicalEdge) []Step {
	out := make([]Step, len(edges))
	for i, edge := range edges {
		out[i] = Step{From: edge.From, To: edge.To, ToTarget: edge.ToTarget, Kind: string(edge.Kind), Evidence: append([]EdgeEvidence(nil), edge.Evidence...), Observed: edge.Observed, ToFinding: edge.Finding}
	}
	return out
}

func (p Path) finding() FindingInput { return p.Nodes[len(p.Nodes)-1].Finding.Input }

func (p Path) observed() bool {
	for _, e := range p.Edges {
		if !e.Observed {
			return false
		}
	}
	return true
}

func (p Path) reachable() bool {
	f := p.finding()
	return f.Confirmed && f.Reachability == "reachable"
}

func appendPathField(b []byte, value string) []byte {
	b = strconv.AppendInt(b, int64(len(value)), 10)
	b = append(b, ':')
	return append(b, value...)
}

func pathID(tenant shared.ID, nodes []Node, edges []LogicalEdge) string {
	// The canonical sequence contains tenant, observation, risk, and reachability inputs.
	b := make([]byte, 0, 256)
	b = append(b, "tenant"...)
	b = appendPathField(b, string(tenant))
	for _, n := range nodes {
		if n.Asset != nil {
			b = append(b, "asset"...)
			b = appendPathField(b, string(n.Asset.Asset.ID))
			continue
		}
		f := n.Finding.Input
		b = append(b, "finding"...)
		b = appendPathField(b, string(f.Target.Kind))
		b = appendPathField(b, string(f.Target.ID))
		b = appendPathField(b, f.Finding.CVSSVector)
		b = appendPathField(b, strconv.FormatFloat(f.Finding.RiskScore, 'g', -1, 64))
		b = appendPathField(b, string(f.Finding.Severity))
		b = appendPathField(b, strconv.FormatBool(f.Finding.KEV))
		b = appendPathField(b, string(f.Reachability))
		b = appendPathField(b, string(f.Tier))
		b = appendPathField(b, strconv.FormatBool(f.Confirmed))
		b = appendPathField(b, string(f.Provenance))
	}
	for _, e := range edges {
		b = append(b, "edge"...)
		b = appendPathField(b, string(e.From))
		b = appendPathField(b, string(e.To))
		b = appendPathField(b, string(e.ToTarget))
		b = appendPathField(b, string(e.Kind))
		for _, x := range e.Evidence {
			b = append(b, "evidence"...)
			b = appendPathField(b, string(x.Producer))
			b = appendPathField(b, string(x.Provenance))
			b = appendPathField(b, string(x.Confidence))
		}
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SortPaths applies the report ordering: risk first, then evidence quality and stable ID.
func SortPaths(paths []Path) {
	sort.SliceStable(paths, func(i, j int) bool {
		a, b := paths[i], paths[j]
		af, bf := a.finding().Finding, b.finding().Finding
		if af.KEV != bf.KEV {
			return af.KEV
		}
		if af.RiskScore != bf.RiskScore {
			return af.RiskScore > bf.RiskScore
		}
		ac, aok := shared.CVSSv3BaseScore(af.CVSSVector)
		bc, bok := shared.CVSSv3BaseScore(bf.CVSSVector)
		if aok != bok {
			return aok
		}
		if ac != bc {
			return ac > bc
		}
		if ar, br := shared.SeverityRank(af.Severity), shared.SeverityRank(bf.Severity); ar != br {
			return ar > br
		}
		if a.observed() != b.observed() {
			return a.observed()
		}
		if a.reachable() != b.reachable() {
			return a.reachable()
		}
		if len(a.Uncertainties) != len(b.Uncertainties) {
			return len(a.Uncertainties) < len(b.Uncertainties)
		}
		if len(a.Edges) != len(b.Edges) {
			return len(a.Edges) < len(b.Edges)
		}
		return a.ID < b.ID
	})
}

func pathUncertainties(edges []LogicalEdge, f FindingInput) []Uncertainty {
	u := make([]Uncertainty, 0, len(edges)+1)
	for i, e := range edges {
		if !e.Observed {
			u = append(u, Uncertainty(string(UncertaintyInferredEdge)+":"+strconv.Itoa(i+1)))
		}
	}
	if !f.Confirmed {
		u = append(u, UncertaintyUnconfirmedReachability)
	}
	switch f.Reachability {
	case "":
		u = append(u, UncertaintyMissingReachability)
	case "unknown":
		u = append(u, UncertaintyUnknownReachability)
	}
	return u
}
