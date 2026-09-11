package ownadvisory

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// This file parses a RESF/Apollo OSV LIST document (the format at apollo.build.resf.org/api/v3/osv) into the
// owned normalized advisory shape. Rocky Linux publishes its RLSA security advisories through Apollo as OSV,
// but wrapped in an {"advisories": [ <osv>, ... ]} envelope, with the advisory id being the RLSA and the CVEs
// listed in the OSV "upstream" field (not "aliases"). The plain ParseOSV keys by the document id, so it would
// store RLSA-keyed rows that the CVE-keyed matcher and corpus never join; this parser instead emits one
// advisory PER upstream CVE, carrying the RLSA's affected packages, so a Rocky component matches by CVE like
// every other source.
//
// The affected ecosystem ("Rocky Linux:8") and [0, fixed) ranges come straight from the OSV data (which the
// scan side keys identically for a rocky rpm component), so no re-derivation is needed. When the same CVE
// fixes one package in several RLSAs, the fixed boundary is resolved the same way as the Amazon updateinfo
// feed: the max within a release lineage, and a package fixed across multiple lineages is skipped rather than
// emitted with a lineage-blind range that would false-match a package fixed in the other lineage.

type apolloOSVList struct {
	Advisories []osvDoc `json:"advisories"`
}

// ParseRockyOSV parses a RESF/Apollo OSV list page into advisories keyed by CVE.
func ParseRockyOSV(content []byte) ([]advisory.Advisory, error) {
	if int64(len(content)) > maxOVALFileBytes {
		return nil, fmt.Errorf("%w: OSV list exceeds %d bytes", shared.ErrValidation, maxOVALFileBytes)
	}
	var list apolloOSVList
	if err := json.Unmarshal(content, &list); err != nil {
		return nil, fmt.Errorf("parse rocky osv list: %w", err)
	}
	byCVE := map[string]*rpmCVEMerge{}
	order := make([]string, 0)
	for i := range list.Advisories {
		doc := list.Advisories[i]
		if doc.Withdrawn != "" {
			continue // a retracted advisory is a guaranteed false positive
		}
		affected := osvAffectedPackages(doc)
		if len(affected) == 0 {
			continue
		}
		cves := rockyCVEs(doc)
		if len(cves) == 0 {
			continue
		}
		summary := firstNonEmpty(doc.Summary, doc.Details)
		for _, cve := range cves {
			a := byCVE[cve]
			if a == nil {
				a = &rpmCVEMerge{summary: summary, evrs: map[string]map[string]struct{}{}}
				byCVE[cve] = a
				order = append(order, cve)
			}
			for _, ap := range affected {
				if !isRockyEcosystem(ap.Ecosystem) {
					continue // a Rocky-only ingester must never write another distro's ecosystem (cross-distro false match)
				}
				fixed := rockyZeroBoundedFixed(ap)
				if fixed == "" {
					continue // only a genuine [0, fixed) ECOSYSTEM boundary is a sound rpm range
				}
				key := ap.Ecosystem + "\x00" + ap.Package
				set := a.evrs[key]
				if set == nil {
					set = map[string]struct{}{}
					a.evrs[key] = set
					a.order = append(a.order, key)
				}
				set[fixed] = struct{}{}
			}
		}
	}
	out := make([]advisory.Advisory, 0, len(order))
	for _, cve := range order {
		a := byCVE[cve]
		var affected []advisory.AffectedPackage
		for _, key := range a.order {
			ecosystem, pkg, _ := strings.Cut(key, "\x00")
			fixed := resolveRpmFixedInLineage(ecosystem, a.evrs[key])
			if fixed == "" {
				continue // no version, or fixed across multiple lineages: skip (a safe coverage gap)
			}
			affected = append(affected, advisory.AffectedPackage{
				Ecosystem:    ecosystem,
				Package:      pkg,
				Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
				FixedVersion: fixed,
			})
		}
		if len(affected) == 0 {
			continue
		}
		out = append(out, advisory.Advisory{ID: cve, Summary: a.summary, Affected: affected})
	}
	return out, nil
}

// cveID matches a well-formed CVE identifier, so a malformed pseudo-CVE from a source is never stored as an id
// (a bad id could only ever fail to join, but rejecting it keeps the store's key space clean).
var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// rockyCVEs returns the distinct CVE ids of an Apollo OSV document, from its "upstream" list (where Rocky puts
// them) and its aliases, in order.
func rockyCVEs(doc osvDoc) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if cveID.MatchString(id) && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range doc.Upstream {
		add(id)
	}
	for _, id := range doc.Aliases {
		add(id)
	}
	add(doc.ID)
	return out
}

// isRockyEcosystem reports whether eco is a Rocky Linux ecosystem key ("Rocky Linux:<major>"). This
// source-specific ingester must only ever write Rocky rows: emitting another distro's ecosystem verbatim from a
// malformed Apollo entry would false-match that distro by CVE and package.
func isRockyEcosystem(eco string) bool {
	major, ok := strings.CutPrefix(eco, "Rocky Linux:")
	return ok && major != "" && isAllDigits(major)
}

// rockyZeroBoundedFixed returns the fixed rpm EVR of an affected package only when its range is a genuine
// [0, fixed) ECOSYSTEM range: an rpm distro advisory marks a package affected from version 0 until the fixed
// build. It rejects a non-ECOSYSTEM range, a non-zero "introduced", and a "last_affected" upper bound, so a
// non-conforming entry becomes a skip (a safe coverage gap) rather than a widened [0, fixed) range that would
// false-match an older, genuinely-unaffected rpm.
func rockyZeroBoundedFixed(ap advisory.AffectedPackage) string {
	for _, r := range ap.Ranges {
		if r.Type != "ECOSYSTEM" {
			continue
		}
		fixed := ""
		conforming := true
		for _, ev := range r.Events {
			switch {
			case ev.Introduced != "" && ev.Introduced != "0":
				conforming = false // a non-zero introduced is not a [0, fixed) range
			case ev.LastAffected != "":
				conforming = false // a closed upper bound is not a [0, fixed) range
			case ev.Fixed != "" && fixed == "":
				fixed = ev.Fixed
			}
		}
		if conforming && fixed != "" {
			return fixed
		}
	}
	return ""
}
