package sbom

import "sort"

// Cross-check (the swappability invariant as a feature, SBOM side): run ≥2 SBOM
// PRODUCERS (an owned parser registry + a vendor tool like Syft) over the same target and record where
// their component sets DISAGREE. A component both producers emit is a confidence signal; one only a single
// producer emits is the human-review signal – surfaced, NEVER auto-resolved. This is the pure, deterministic
// disagreement record the cross-check use case builds on (mirrors vulnerability.CrossCheck).

// CrossCheckItem is one component and which run producers did / did not emit it.
type CrossCheckItem struct {
	Name      string
	Version   string
	PURL      string
	Reporters []string // the run producers that emitted it (sorted, distinct)
	Missing   []string // run producers that did NOT emit it (sorted) – empty for an agreed item
}

// CrossCheckReport partitions the union of components by whether ALL run producers emitted them. Producers
// is the set of SBOM producers that were EXECUTED (so a component emitted by only 1 of 2 producers is
// flagged, even though the other simply emitted nothing for it). Deterministic order (by component identity).
type CrossCheckReport struct {
	Producers     []string         // the SBOM producers that ran (sorted, distinct)
	Agreed        []CrossCheckItem // emitted by EVERY run producer
	Disagreements []CrossCheckItem // emitted by some but not all run producers – the review signal
}

// CrossCheck diffs each producer's component set. For every component (keyed by ComponentID – PURL, else
// name@version, else name) it compares the producers that emitted it against the run-producer set: emitted by
// every producer ⇒ Agreed; missed by any ⇒ Disagreement. Pure + deterministic.
//
// producerNames SHOULD be the producers actually EXECUTED. The effective set is the UNION of producerNames
// with every doc's Source: the union only ever EXPANDS the declared set (so a producer that ran but emitted
// an empty SBOM is still flagged Missing on every component it lacked – never weakened), keeps the report
// self-consistent if the caller passes an incomplete set, and prevents an empty producerNames from emitting a
// FALSE "Agreed" (a lone producer then reads as a single-producer, trivially-agreed scan).
func CrossCheck(producerNames []string, docs []*SBOM) CrossCheckReport {
	reportersByID := map[string]map[string]bool{} // componentID -> set of producer names that emitted it
	repr := map[string]Component{}                // componentID -> a representative component (Name/Version/PURL)
	all := append([]string{}, producerNames...)
	for _, doc := range docs {
		if doc == nil {
			continue
		}
		all = append(all, doc.Source) // a producer is never absent from the run set, even with 0 components
		for _, c := range doc.Components {
			id := ComponentID(c.Name, c.Version, c.PURL)
			if id == "" {
				continue
			}
			if reportersByID[id] == nil {
				reportersByID[id] = map[string]bool{}
				repr[id] = c
			}
			reportersByID[id][doc.Source] = true
		}
	}
	run := uniqueSorted(all)
	report := CrossCheckReport{Producers: run}

	ids := make([]string, 0, len(reportersByID))
	for id := range reportersByID {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic component order
	for _, id := range ids {
		reporters := setToSorted(reportersByID[id])
		c := repr[id]
		item := CrossCheckItem{
			Name:      c.Name,
			Version:   c.Version,
			PURL:      c.PURL,
			Reporters: reporters,
			Missing:   difference(run, reporters),
		}
		if len(item.Missing) == 0 {
			report.Agreed = append(report.Agreed, item)
		} else {
			report.Disagreements = append(report.Disagreements, item)
		}
	}
	return report
}

// uniqueSorted returns the distinct, sorted, non-empty elements of in.
func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// setToSorted returns the keys of set as a sorted slice.
func setToSorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// difference returns the elements of a not present in b (both sorted+deduped); preserves a's order. Used to
// compute the run producers that did NOT emit a component.
func difference(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, x := range b {
		inB[x] = true
	}
	var out []string
	for _, x := range a {
		if !inB[x] {
			out = append(out, x)
		}
	}
	return out
}
