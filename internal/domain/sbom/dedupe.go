package sbom

// DedupeComponents collapses duplicate component entries for the SAME package into one, unioning
// their license data. SBOM generators (notably Syft) routinely emit the same package as several
// components from different evidence sources – e.g. one entry carrying the resolved license and a
// second carrying none. Left as-is, the license-less twin reads as an "UNKNOWN license" everywhere
// downstream (license coverage, the component audit, and the Excel export) even though the package's
// license WAS detected on its sibling – the phantom-UNKNOWN customers reported.
//
// Identity is the PURL when present (same PURL ⇒ same package), else name@version as a fallback for
// the rare PURL-less entry. Components with no identity at all (no PURL, no name+version) are kept
// as-is. The first occurrence wins for scalar fields; a later occurrence only FILLS values the first
// left empty (license list, location, layer, license provenance) – so merging a licensed entry with
// an empty one yields the licensed result and never drops information.
//
// Layer note (Epic D): identity intentionally does NOT include LayerID – the phantom-UNKNOWN twin is
// precisely a same-package entry with an empty LayerID, so keying on layer would stop the merge and
// reintroduce the bug. The trade is that a package legitimately present in two layers under the same
// identity keeps only the first LayerID; near-zero in practice (same PURL+version across layers is
// uncommon) and acceptable versus the customer-facing UNKNOWN noise.
func DedupeComponents(comps []Component) []Component {
	out := make([]Component, 0, len(comps))
	index := make(map[string]int, len(comps)) // identity key -> position in out
	for _, c := range comps {
		key := componentIdentity(c)
		if key == "" { // unidentifiable: never merge (could collapse distinct anonymous entries)
			out = append(out, c)
			continue
		}
		if pos, ok := index[key]; ok {
			out[pos] = mergeComponents(out[pos], c)
			continue
		}
		index[key] = len(out)
		out = append(out, c)
	}
	return out
}

// componentIdentity is the merge key: the PURL if set (authoritative package identity), else
// name@version. Returns "" when the component has neither, so it is never merged with another.
func componentIdentity(c Component) string {
	if c.PURL != "" {
		return "purl\x00" + c.PURL
	}
	if c.Name != "" && c.Version != "" {
		return "nv\x00" + c.Name + "\x00" + c.Version
	}
	return ""
}

// mergeComponents folds src into dst: licenses are unioned (deduped), and any scalar field dst left
// empty is filled from src. dst (the earlier occurrence) otherwise wins, keeping the result stable
// and order-preserving.
func mergeComponents(dst, src Component) Component {
	dst.Licenses = unionLicenses(dst.Licenses, src.Licenses)
	if dst.Location == "" {
		dst.Location = src.Location
	}
	if dst.Scope == "" || dst.Scope == ScopeUnknown {
		if src.Scope != "" && src.Scope != ScopeUnknown {
			dst.Scope = src.Scope
		}
	}
	if dst.LayerID == "" {
		dst.LayerID = src.LayerID
	}
	// License provenance follows the license data: if dst had none and src supplied some, adopt
	// src's source/confidence and clear the "unknown" reason so it isn't reported as unresolved.
	if dst.LicenseSource == "" {
		dst.LicenseSource = src.LicenseSource
	}
	if dst.LicenseConfidence == "" {
		dst.LicenseConfidence = src.LicenseConfidence
	}
	if dst.LicenseConfidencePct == 0 {
		dst.LicenseConfidencePct = src.LicenseConfidencePct
	}
	if len(dst.Licenses) > 0 {
		dst.UnknownReason = ""
	} else if dst.UnknownReason == "" {
		dst.UnknownReason = src.UnknownReason
	}
	// Supplier + its provenance move together so the source label always describes the value it accompanies.
	if dst.Supplier == "" {
		dst.Supplier = src.Supplier
		dst.SupplierSource = src.SupplierSource
	}
	// Integrity digests: adopt the twin's when this entry has none, so a Syft phantom-UNKNOWN twin that
	// carries the only checksum/SHA1 doesn't drop it on merge (mirrors the license union above).
	if dst.SHA1 == "" {
		dst.SHA1 = src.SHA1
	}
	if len(dst.Checksums) == 0 {
		dst.Checksums = src.Checksums
	}
	// First-party is a true OR: if either evidence source identifies it as the project's own module.
	dst.FirstParty = dst.FirstParty || src.FirstParty
	return dst
}

// unionLicenses concatenates two license lists, dropping duplicates (by SPDXID, else Name).
func unionLicenses(a, b []License) []License {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]License, 0, len(a)+len(b))
	add := func(licenses []License) {
		for _, l := range licenses {
			key := l.SPDXID
			if key == "" {
				key = l.Name
			}
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, l)
		}
	}
	add(a)
	add(b)
	return out
}
