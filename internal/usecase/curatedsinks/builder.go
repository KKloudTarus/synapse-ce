// Package curatedsinks bridges the curated vulnerable-methods DB (advisory.CuratedSymbols) into the taint
// engine: each CONFIRMED curated vulnerable API becomes a taint sink, so the dataflow engine proves
// attacker input reaches that exact function (EPIC #1042 2.2, the curated moat). Only confirmed, valid
// curated symbols become sinks (SeedSymbols gates this), and every sink carries provenance back to the
// advisory and the curation act.
package curatedsinks

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

// FromAdvisories builds the curated taint sinks for the given advisories. For each advisory it emits one
// sink per CONFIRMED curated symbol (and its overloads/aliases), tagged with the advisory's weakness (its
// first CWE, when present), a stable per-advisory rule id ("reach-<advisoryID>"), and provenance. A
// candidate or malformed curated symbol contributes nothing (SeedSymbols returns none). Sinks are
// de-duplicated by (symbol, rule) so the same vulnerable API listed twice yields one sink; the result is
// safe to append to a taint.Catalog (a sink whose function the target never calls simply never fires).
func FromAdvisories(advs []advisory.Advisory) []taint.Sink {
	var out []taint.Sink
	seen := map[string]bool{}
	for _, a := range advs {
		cwe := ""
		if len(a.CWEs) > 0 {
			cwe = a.CWEs[0]
		}
		rule := "reach-" + a.ID
		for _, aff := range a.Affected {
			for _, cs := range aff.CuratedSymbols {
				if cs.Status != advisory.CuratedConfirmed {
					continue
				}
				prov := taint.SinkProvenance{
					Advisory:  a.ID,
					Source:    cs.Provenance.Source,
					Reference: cs.Provenance.Reference,
					Curator:   cs.Provenance.Curator,
				}
				for _, sym := range cs.SeedSymbols() {
					key := sym + "|" + rule
					if sym == "" || seen[key] {
						continue
					}
					seen[key] = true
					out = append(out, taint.CuratedSink(sym, cwe, rule, prov))
				}
			}
		}
	}
	return out
}
