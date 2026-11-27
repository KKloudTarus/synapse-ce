package advisory

import (
	"sort"
	"strings"
)

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

// RecordAliases indexes edges by advisory record and returns a lookup from one id to every id of the records
// that name it: each such record's own id and its aliases, in the spelling the edges carry, sorted. Ids
// compare case-insensitively. Unlike Closure it never follows a chain from one record into another. A record
// whose ids name more than one distinct CVE is ambiguous: its non-CVE ids may be either vulnerability, so they
// resolve to nil and never appear in another id's result, and a VEX statement naming one cannot reach a
// finding reported under another id. An id no unambiguous record names, or whose records together name more
// than one CVE, returns nil.
func RecordAliases(edges []AliasEdge) func(id string) []string {
	records := map[string][]string{} // normalized record id -> its ids, record id first
	named := map[string][]string{}   // normalized id -> normalized ids of the records naming it
	for _, e := range edges {
		c, a := normalizeID(e.CanonicalID), normalizeID(e.AliasID)
		if c == "" || a == "" {
			continue
		}
		if _, ok := records[c]; !ok {
			records[c] = []string{e.CanonicalID}
			named[c] = append(named[c], c)
		}
		records[c] = append(records[c], e.AliasID)
		named[a] = append(named[a], c)
	}
	// A record naming several CVEs is ambiguous, and so is each of its ids that is not itself a CVE: such an id
	// (the record's GHSA, say) may be either vulnerability. An ambiguous record contributes nothing, and an
	// ambiguous id neither resolves nor appears in another id's result, since a statement naming it could
	// mean the other CVE.
	ambiguousRecord, ambiguousID := map[string]bool{}, map[string]bool{}
	for c, members := range records {
		if distinctCVEs(members) <= 1 {
			continue
		}
		ambiguousRecord[c] = true
		for _, m := range members {
			if distinctCVEs([]string{m}) == 0 {
				ambiguousID[normalizeID(m)] = true
			}
		}
	}
	return func(id string) []string {
		key := normalizeID(id)
		if ambiguousID[key] {
			return nil
		}
		seen := map[string]bool{}
		var out []string
		for _, record := range named[key] {
			if ambiguousRecord[record] {
				continue
			}
			for _, member := range records[record] {
				if k := normalizeID(member); !seen[k] && !ambiguousID[k] {
					seen[k] = true
					out = append(out, member)
				}
			}
		}
		// Two unambiguous records can still name different CVEs between them (GHSA-y aliased by CVE-1's
		// record and by CVE-2's), so the union is held to the same rule.
		if distinctCVEs(out) > 1 {
			return nil
		}
		sort.Slice(out, func(i, j int) bool { return normalizeID(out[i]) < normalizeID(out[j]) })
		return out
	}
}

// distinctCVEs counts the distinct CVEs among ids, reading a namespaced wrapper (DEBIAN-CVE-…) as the CVE it
// wraps.
func distinctCVEs(ids []string) int {
	seen := map[string]bool{}
	for _, id := range ids {
		u := normalizeID(id)
		if !strings.HasPrefix(u, "CVE-") {
			i := strings.Index(u, "-CVE-")
			if i < 0 {
				continue
			}
			u = u[i+1:]
		}
		seen[u] = true
	}
	return len(seen)
}
