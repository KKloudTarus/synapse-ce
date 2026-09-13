package taintscan

import (
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// correlateSASTFindings joins a reached taint sink to an SCA finding only when the sink symbol and an
// advisory affected symbol canonically match as a whole symbol. It is deliberately stricter than the
// raise-only tail matching used by some reachability engines: a dataflow link is promotion input, so a
// same-named local/helper function must never be attributed to an advisory.
//
// ReachabilitySubject already carries the per-finding, version-correct affected-symbol set produced by the
// SCA pipeline. The result is sorted and duplicate-free so the Claim survives rescans without churn.
func correlateSASTFindings(language symbolcanon.Language, sinkSymbols []string, subjects []ports.ReachabilitySubject) []judgment.SASTFindingCorrelation {
	if len(sinkSymbols) == 0 || len(subjects) == 0 {
		return nil
	}

	type candidate struct {
		link      judgment.SASTFindingCorrelation
		canonical string
	}
	links := make([]candidate, 0)
	for _, sink := range sinkSymbols {
		canonicalSink := symbolcanon.Canonicalize(language, sink)
		// A bare leaf such as "Parse" cannot safely identify a library function. Require the immediate
		// owner/module too, and refuse a binary name that was not demangled at extraction time.
		if symbolcanon.LooksMangled(sink) || len(canonicalSink.Segments) < 2 {
			continue
		}
		for _, subject := range subjects {
			if subject.FindingID.IsZero() {
				continue
			}
			for _, affected := range subject.Symbols {
				canonicalAffected := symbolcanon.Canonicalize(language, affected)
				if symbolcanon.LooksMangled(affected) || len(canonicalAffected.Segments) < 2 || !symbolcanon.Equal(canonicalSink, canonicalAffected) {
					continue
				}
				links = append(links, candidate{
					link:      judgment.SASTFindingCorrelation{FindingID: subject.FindingID, SinkSymbol: sink, AffectedSymbol: affected},
					canonical: canonicalAffected.String(),
				})
			}
		}
	}
	if len(links) == 0 {
		return nil
	}
	sort.Slice(links, func(i, j int) bool {
		left, right := links[i], links[j]
		if left.link.FindingID != right.link.FindingID {
			return left.link.FindingID < right.link.FindingID
		}
		if left.link.SinkSymbol != right.link.SinkSymbol {
			return left.link.SinkSymbol < right.link.SinkSymbol
		}
		if left.canonical != right.canonical {
			return left.canonical < right.canonical
		}
		return left.link.AffectedSymbol < right.link.AffectedSymbol
	})

	seen := make(map[string]struct{}, len(links))
	out := make([]judgment.SASTFindingCorrelation, 0, len(links))
	for _, item := range links {
		key := item.link.FindingID.String() + "\x00" + item.link.SinkSymbol + "\x00" + item.canonical
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item.link)
	}
	return out
}
