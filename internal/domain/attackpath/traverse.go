package attackpath

import (
	"context"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	defaultMaxLength = 32
	defaultMaxPaths  = 100
)

// Query filters paths. All non-empty filters compose with AND.
type Query struct {
	Target        shared.ID
	Entrypoint    shared.ID
	Finding       shared.ID
	FindingTarget *FindingTarget
}

// Limits bounds traversal work. Now is injectable so deadline behavior is deterministic in tests.
type Limits struct {
	MaxLength   int
	MaxPaths    int
	MaxDuration time.Duration
	Now         func() time.Time
}

// BoundReport identifies a normal, resource-bound partial traversal.
type BoundReport struct {
	MaxLength       int           `json:"maxLength"`
	MaxPaths        int           `json:"maxPaths"`
	MaxDuration     time.Duration `json:"maxDuration"`
	Truncated       bool          `json:"truncated"`
	LengthHit       bool          `json:"lengthHit"`
	PathsHit        bool          `json:"pathsHit"`
	TargetPathsHit  bool          `json:"targetPathsHit"`
	FindingPathsHit bool          `json:"findingPathsHit"`
	WallClockHit    bool          `json:"wallClockHit"`
}

// Result is the sorted path set and any traversal bounds reached.
type Result struct {
	Paths  []Path      `json:"paths"`
	Bounds BoundReport `json:"bounds"`
}

// Traverse derives paths from exposure assets, or Query.Entrypoint when selected.
func (g *Graph) Traverse(ctx context.Context, q Query, limits Limits) (Result, error) {
	if g == nil {
		return Result{}, validation("graph is required")
	}
	if q.Target != "" {
		if _, ok := g.Assets[q.Target]; !ok {
			return Result{}, validation("target %q is not an asset", q.Target)
		}
	}
	if q.Entrypoint != "" {
		if _, ok := g.Assets[q.Entrypoint]; !ok {
			return Result{}, validation("entrypoint %q is not an asset", q.Entrypoint)
		}
	}
	if q.FindingTarget != nil && (!q.FindingTarget.Kind.Valid() || q.FindingTarget.ID == "") {
		return Result{}, validation("finding target is invalid")
	}
	if limits.MaxLength <= 0 {
		limits.MaxLength = defaultMaxLength
	}
	if limits.MaxPaths <= 0 {
		limits.MaxPaths = defaultMaxPaths
	}
	if limits.Now == nil {
		limits.Now = time.Now
	}
	deadline := time.Time{}
	if limits.MaxDuration > 0 {
		deadline = limits.Now().Add(limits.MaxDuration)
	}

	adj := make(map[shared.ID][]LogicalEdge, len(g.Assets))
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e)
	}
	for _, edges := range adj {
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].To != edges[j].To {
				return edges[i].To < edges[j].To
			}
			if edges[i].ToTarget != edges[j].ToTarget {
				return edges[i].ToTarget < edges[j].ToTarget
			}
			return edges[i].Kind < edges[j].Kind
		})
	}
	roots := make([]shared.ID, 0)
	if q.Entrypoint != "" {
		roots = append(roots, q.Entrypoint)
	} else {
		for id, n := range g.Assets {
			if n.Asset.Kind == asset.KindExposure {
				roots = append(roots, id)
			}
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })

	var out Result
	out.Bounds = BoundReport{MaxLength: limits.MaxLength, MaxPaths: limits.MaxPaths, MaxDuration: limits.MaxDuration}
	perGroup := make(map[FindingTarget][]Path)
	var walk func([]Node, []LogicalEdge, map[shared.ID]bool) error
	walk = func(nodes []Node, edges []LogicalEdge, seen map[shared.ID]bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !deadline.IsZero() && !limits.Now().Before(deadline) {
			out.Bounds.WallClockHit = true
			out.Bounds.Truncated = true
			return nil
		}
		for _, e := range adj[nodes[len(nodes)-1].ID()] {
			if !deadline.IsZero() && !limits.Now().Before(deadline) {
				out.Bounds.WallClockHit = true
				out.Bounds.Truncated = true
				return nil
			}
			if len(edges) >= limits.MaxLength {
				out.Bounds.LengthHit = true
				out.Bounds.Truncated = true
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if e.Finding {
				target := FindingTarget{ID: e.To, Kind: e.ToTarget}
				if target.Kind == "" {
					target.Kind = TargetCanonical
				}
				f := g.Findings[target].Input
				if (f.Confirmed && f.Reachability == "not_reachable") || (q.Finding != "" && target.ID != q.Finding) || (q.FindingTarget != nil && target != *q.FindingTarget) {
					continue
				}
				allNodes := append(append([]Node(nil), nodes...), Node{Finding: &FindingNode{Input: f}})
				allEdges := append(append([]LogicalEdge(nil), edges...), e)
				containsTarget := q.Target == ""
				for _, n := range allNodes {
					containsTarget = containsTarget || n.Asset != nil && n.Asset.Asset.ID == q.Target
				}
				if !containsTarget {
					continue
				}
				u := pathUncertainties(allEdges, f)
				p := Path{Nodes: allNodes, Edges: allEdges, Steps: steps(allEdges), Uncertainties: u, Confident: len(u) == 0}
				p.ID = pathID(g.TenantID, p.Nodes, p.Edges)
				group := target
				if q.Target != "" {
					group = FindingTarget{ID: q.Target}
				}
				perGroup[group] = append(perGroup[group], p)
				SortPaths(perGroup[group])
				if len(perGroup[group]) > limits.MaxPaths {
					perGroup[group] = perGroup[group][:limits.MaxPaths]
					out.Bounds.PathsHit = true
					out.Bounds.Truncated = true
					if q.Target != "" {
						out.Bounds.TargetPathsHit = true
					} else {
						out.Bounds.FindingPathsHit = true
					}
				}
				continue
			}
			if seen[e.To] {
				continue
			}
			seen[e.To] = true
			n := g.Assets[e.To]
			err := walk(append(nodes, Node{Asset: &n}), append(edges, e), seen)
			delete(seen, e.To)
			if err != nil {
				return err
			}
		}
		return nil
	}
	for _, root := range roots {
		n := g.Assets[root]
		if err := walk([]Node{{Asset: &n}}, nil, map[shared.ID]bool{root: true}); err != nil {
			return Result{}, err
		}
		if out.Bounds.WallClockHit {
			break
		}
	}
	for _, paths := range perGroup {
		out.Paths = append(out.Paths, paths...)
	}
	SortPaths(out.Paths)
	return out, nil
}
