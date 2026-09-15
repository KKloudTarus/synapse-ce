package sast

import "github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulemeta"

// canonicalBuiltinRules keeps generated legacy keys available to catalog/golden
// parity while ensuring the production scanner runs only the reviewed canonical
// detector for true semantic aliases. If a future regeneration accidentally
// drops the canonical detector first, the alias is retained rather than losing
// coverage.
func canonicalBuiltinRules(in []rule) []rule {
	present := make(map[string]bool, len(in))
	for _, entry := range in {
		present[entry.id] = true
	}

	out := make([]rule, 0, len(in))
	for _, entry := range in {
		canonical := rulemeta.CanonicalKey(entry.id)
		if canonical != entry.id && present[canonical] {
			continue
		}
		entry.title = rulemeta.DisplayName(entry.id, entry.title)
		out = append(out, entry)
	}
	return out
}
