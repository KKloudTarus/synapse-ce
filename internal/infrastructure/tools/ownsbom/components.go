package ownsbom

import "github.com/KKloudTarus/synapse-ce/internal/domain/sbom"

// componentSet accumulates a parser's components, de-duplicating by PURL identity – the same identity the
// registry's cross-parser second pass keys on (sbom.ComponentID, which is the PURL when one is set). It is
// pure DATA (no I/O): each parser builds the Component with its OWN ecosystem encoding (npm %40, PyPI
// PEP-503, …) and the shared Location/Scope, then hands it to add; the set owns the dedup invariant so it
// can't drift between parsers. A component missing a name, version, or PURL is dropped – an SBOM entry must
// be identifiable and matchable against an advisory.
type componentSet struct {
	seen  map[string]bool
	comps []sbom.Component
}

// newComponentSet returns an empty set.
func newComponentSet() *componentSet { return &componentSet{seen: map[string]bool{}} }

// add records a component unless it is incomplete (no name/version/PURL) or a PURL-duplicate of one held.
func (s *componentSet) add(c sbom.Component) {
	if c.Name == "" || c.Version == "" || c.PURL == "" || s.seen[c.PURL] {
		return
	}
	s.seen[c.PURL] = true
	s.comps = append(s.comps, c)
}

// components returns the accumulated, de-duplicated components.
func (s *componentSet) components() []sbom.Component { return s.comps }
