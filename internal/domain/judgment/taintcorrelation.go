package judgment

import (
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
)

// VulnerableSymbolIndex is a prebuilt reverse index from a canonical vulnerable symbol to the SCA findings
// whose advisory lists it. It correlates a taint flow's SINK to the finding(s) it exploits: a taint flow
// whose dangerous callee is an advisory's vulnerable function is the strongest exploitability signal there
// is, because the vulnerable code is not merely present, it is reached by attacker-controlled data.
//
// It is built ONCE from an advisory index (finding id -> vulnerable symbols) so per-flow correlation is an
// O(1) map lookup, not a rescan of every finding's symbols per taint proposal. It is CONSERVATIVE, to never
// fabricate a link (the #1050 acceptance: no link when the sink is not an advisory symbol):
//   - Both sides are canonicalized under ONE language (the scan's dialect), so a cross-dialect token
//     collision cannot collapse two distinct symbols into a match.
//   - A symbol must canonicalize to at least owner + member (>= 2 segments); a bare one-segment name like
//     "Parse" is not a sound identity and is dropped, on both the vulnerable and the sink side.
//   - A mangled (un-demangled) symbol is never an index key or a correlation key.
type VulnerableSymbolIndex struct {
	lang        symbolcanon.Language
	byCanonical map[string][]shared.ID
}

// NewVulnerableSymbolIndex builds the reverse index for one scan language. vulnByFinding maps a finding id
// to its advisory's vulnerable symbols. Malformed, mangled, or single-segment symbols are dropped; each
// finding id appears at most once per canonical key, and the per-key id lists are sorted for deterministic
// correlation regardless of map iteration order.
func NewVulnerableSymbolIndex(lang symbolcanon.Language, vulnByFinding map[shared.ID][]string) VulnerableSymbolIndex {
	idx := VulnerableSymbolIndex{lang: lang, byCanonical: map[string][]shared.ID{}}
	seen := map[string]map[shared.ID]bool{}
	for findingID, symbols := range vulnByFinding {
		if findingID.IsZero() {
			continue
		}
		for _, s := range symbols {
			key, ok := idx.canonicalKey(s)
			if !ok {
				continue
			}
			if seen[key] == nil {
				seen[key] = map[shared.ID]bool{}
			}
			if !seen[key][findingID] {
				seen[key][findingID] = true
				idx.byCanonical[key] = append(idx.byCanonical[key], findingID)
			}
		}
	}
	for key := range idx.byCanonical {
		ids := idx.byCanonical[key]
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	}
	return idx
}

// canonicalKey returns the canonical "::"-joined key for a symbol under the index language, and false when
// the symbol is mangled or canonicalizes to fewer than owner + member (2) segments.
func (i VulnerableSymbolIndex) canonicalKey(symbol string) (string, bool) {
	if symbolcanon.LooksMangled(symbol) {
		return "", false
	}
	c := symbolcanon.Canonicalize(i.lang, symbol)
	if len(c.Segments) < 2 {
		return "", false
	}
	return c.String(), true
}

// Correlate resolves the SCA findings whose advisory vulnerable symbol the taint sink reaches. It returns
// the finding ids (already sorted and de-duplicated), or nil when the sink is not any finding's vulnerable
// symbol, is mangled, or is not a sound owner+member identity, so no correlation is ever fabricated.
func (i VulnerableSymbolIndex) Correlate(sinkSymbol string) []shared.ID {
	if len(i.byCanonical) == 0 {
		return nil
	}
	key, ok := i.canonicalKey(sinkSymbol)
	if !ok {
		return nil
	}
	return i.byCanonical[key]
}

// Empty reports whether the index has no vulnerable symbols (so a caller can skip correlation entirely).
func (i VulnerableSymbolIndex) Empty() bool { return len(i.byCanonical) == 0 }

// CorrelateTaintSink is a convenience for a one-shot correlation: it builds a VulnerableSymbolIndex and
// queries it. Prefer NewVulnerableSymbolIndex + Correlate on the hot path (many sinks against one index) so
// the index is built once rather than per sink.
func CorrelateTaintSink(lang symbolcanon.Language, sinkSymbol string, vulnByFinding map[shared.ID][]string) []shared.ID {
	return NewVulnerableSymbolIndex(lang, vulnByFinding).Correlate(sinkSymbol)
}
