package advisory

import "sort"

// AliasEdge is one row of the owned alias index: an alias id that resolves to a canonical advisory id
// (GHSA-… -> CVE-…, and the like). Each alias maps to exactly one canonical (enforced on ingest), so the
// edge set is a forest of stars plus any canonical-of-canonical chain.
type AliasEdge struct {
	AliasID     string
	CanonicalID string
}

// AliasGraph is the transitive closure of the owned advisory alias index. It answers "which advisory ids are
// the same vulnerability as this one", so two cross-source findings that carry non-overlapping ids - a
// GHSA-only finding and a CVE-only finding for one issue - are recognized as one during correlation without
// relying on the fragile description fallback. Because each alias maps to a single canonical, a component is
// exactly one canonical plus its aliases, so the closure never merges two distinct CVEs. Build is O(edges)
// and every query is a map lookup; both are deterministic and cycle-safe.
type AliasGraph struct {
	parent  map[string]string
	members map[string][]string // component root -> its sorted member ids
}

// NewAliasGraph builds the graph from the alias edges via union-find with path halving. Ids are normalized
// (uppercased, trimmed) so they meet the same key the finding side uses. The component representative is its
// lexicographically smallest id, stable regardless of edge order. A nil/empty edge set yields an empty graph
// whose Closure is the identity, so a caller with no alias data behaves exactly as before.
func NewAliasGraph(edges []AliasEdge) *AliasGraph {
	g := &AliasGraph{parent: map[string]string{}, members: map[string][]string{}}
	for _, e := range edges {
		a, c := normalizeID(e.AliasID), normalizeID(e.CanonicalID)
		if a == "" || c == "" || a == c {
			continue
		}
		g.union(a, c)
	}
	for id := range g.parent {
		root := g.find(id)
		g.members[root] = append(g.members[root], id)
	}
	for root := range g.members {
		sort.Strings(g.members[root])
	}
	return g
}

func (g *AliasGraph) find(x string) string {
	if _, ok := g.parent[x]; !ok {
		g.parent[x] = x
		return x
	}
	root := x
	for g.parent[root] != root {
		root = g.parent[root]
	}
	for g.parent[x] != root { // path halving
		g.parent[x], x = root, g.parent[x]
	}
	return root
}

func (g *AliasGraph) union(a, b string) {
	ra, rb := g.find(a), g.find(b)
	if ra == rb {
		return
	}
	if ra < rb {
		g.parent[rb] = ra
	} else {
		g.parent[ra] = rb
	}
}

// Closure returns every advisory id in the same connected component as id, sorted and including id itself. An
// id the graph never saw returns just itself, so an unknown id is never dropped or spuriously merged.
func (g *AliasGraph) Closure(id string) []string {
	id = normalizeID(id)
	if id == "" {
		return nil
	}
	root, ok := g.rootOf(id)
	if !ok {
		return []string{id}
	}
	return g.members[root]
}

// rootOf returns id's component root WITHOUT mutating the graph, so Closure is safe for concurrent reads
// after construction. An unknown id reports ok=false.
func (g *AliasGraph) rootOf(id string) (string, bool) {
	if _, ok := g.parent[id]; !ok {
		return "", false
	}
	root := id
	for g.parent[root] != root {
		root = g.parent[root]
	}
	return root, true
}

// Expand returns the sorted, de-duplicated union of the closures of every input id. It is the form
// correlation uses to widen a finding's alias set before clustering.
func (g *AliasGraph) Expand(ids []string) []string {
	seen := map[string]struct{}{}
	for _, id := range ids {
		for _, member := range g.Closure(id) {
			seen[member] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
