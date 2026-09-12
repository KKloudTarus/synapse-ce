package ownadvisory

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ParseOSV normalizes one OSV-schema advisory (the OSV.dev bulk-export / vulns/{id} JSON) into the owned
// domain advisory.Advisory. It is a pure parser (no I/O) – the ingest pipeline reads
// the bytes (offline snapshot) and calls this; the store persists the result, keyed in the exact
// OSV-canonical ecosystem/package form the matcher's KEY CONTRACT requires (the OSV `package` block IS
// that canonical form – Maven is already "groupId:artifactId", Go the module path). Fixture-tested,
// mirroring the owned SBOM parsers.
func ParseOSV(data []byte) (advisory.Advisory, error) {
	var doc osvDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return advisory.Advisory{}, fmt.Errorf("parse OSV advisory: %w", err)
	}
	if strings.TrimSpace(doc.ID) == "" {
		return advisory.Advisory{}, fmt.Errorf("%w: OSV advisory has no id", shared.ErrValidation)
	}
	adv := advisory.Advisory{ID: doc.ID, Aliases: doc.Aliases, Summary: firstNonEmpty(doc.Summary, doc.Details)}
	// A non-empty OSV "withdrawn" timestamp means the advisory was retracted; carry it so the matcher
	// skips it (a withdrawn advisory is a guaranteed false positive).
	adv.Withdrawn = strings.TrimSpace(doc.Withdrawn) != ""
	// A curated database_specific.severity label (GHSA/OSV) gives a band for advisories that carry no
	// CVSS vector to score, so an offline scan can still order them. Mirrors the live OSV adapter.
	if lbl, ok := doc.DatabaseSpecific["severity"].(string); ok {
		adv.Severity = shared.SeverityFromLabel(lbl)
	}
	// Prefer a CVSS v3.x vector, falling back to a CVSS v4.0 vector when no v3 is present; compute the
	// base score from the vector (the canonical band source). A v3 vector wins over a v4 one so the
	// offline band matches the historically published v3 score for advisories that carry both.
	var v3vec, v4vec string
	for _, sev := range doc.Severity {
		if !strings.HasPrefix(sev.Type, "CVSS_V") {
			continue
		}
		switch {
		case v3vec == "" && strings.HasPrefix(sev.Score, "CVSS:3."):
			v3vec = sev.Score
		case v4vec == "" && strings.HasPrefix(sev.Score, "CVSS:4.0"):
			v4vec = sev.Score
		}
	}
	// Prefer the first SCORABLE vector, not merely the first v3-looking string: a malformed v3 entry
	// must not suppress a valid v4 one (that would band a real vuln as Unknown).
	switch {
	case v3vec != "":
		if score, ok := shared.CVSSv3BaseScore(v3vec); ok {
			adv.CVSSVector, adv.CVSSScore = v3vec, score
			break
		}
		if v4vec != "" {
			if score, ok := shared.CVSSv40BaseScore(v4vec); ok {
				adv.CVSSVector, adv.CVSSScore = v4vec, score
				break
			}
		}
		adv.CVSSVector = v3vec // keep the v3 vector even if unscorable; the band is derived downstream
	case v4vec != "":
		adv.CVSSVector = v4vec
		if score, ok := shared.CVSSv40BaseScore(v4vec); ok {
			adv.CVSSScore = score
		}
	}
	adv.Affected = osvAffectedPackages(doc)
	return adv, nil
}

// osvAffectedPackages maps an OSV document's affected entries into the domain AffectedPackage shape. An entry
// with no identifiable package is skipped. Shared by ParseOSV and the RESF/Apollo OSV list parser.
func osvAffectedPackages(doc osvDoc) []advisory.AffectedPackage {
	out := make([]advisory.AffectedPackage, 0, len(doc.Affected))
	for _, aff := range doc.Affected {
		if aff.Package.Ecosystem == "" || aff.Package.Name == "" {
			continue // an advisory entry with no identifiable package can't be matched
		}
		out = append(out, advisory.AffectedPackage{
			Ecosystem: aff.Package.Ecosystem, // OSV ecosystem is the canonical form the matcher keys on
			// Normalize the package name to the ecosystem-canonical key (PEP 503 for PyPI) so the stored key
			// matches the SBOM-side lookup – OSV PyPI advisories carry non-normalized names ("Django").
			Package:         canonicalName(aff.Package.Ecosystem, aff.Package.Name),
			Ranges:          mapRanges(aff.Ranges),
			Versions:        aff.Versions,
			FixedVersion:    firstFixed(aff.Ranges),
			AffectedSymbols: osvImportSymbols(aff),
		})
	}
	return out
}

// mapRanges converts OSV ranges (events are untyped {key:value} maps) into the domain Range/Event model.
func mapRanges(ranges []osvRange) []advisory.Range {
	out := make([]advisory.Range, 0, len(ranges))
	for _, r := range ranges {
		dr := advisory.Range{Type: r.Type}
		for _, ev := range r.Events {
			switch {
			case ev["introduced"] != "":
				dr.Events = append(dr.Events, advisory.Event{Introduced: ev["introduced"]})
			case ev["fixed"] != "":
				dr.Events = append(dr.Events, advisory.Event{Fixed: ev["fixed"]})
			case ev["last_affected"] != "":
				dr.Events = append(dr.Events, advisory.Event{LastAffected: ev["last_affected"]})
			case ev["limit"] != "":
				dr.Events = append(dr.Events, advisory.Event{Limit: ev["limit"]})
			}
		}
		out = append(out, dr)
	}
	return out
}

// firstFixed returns the first "fixed" version across an affected entry's ranges, for the remediation
// hint. GIT ranges are skipped – their "fixed" is a commit SHA, a misleading version hint – preferring a
// SEMVER/ECOSYSTEM fix.
func firstFixed(ranges []osvRange) string {
	for _, r := range ranges {
		if r.Type == "GIT" {
			continue
		}
		for _, ev := range r.Events {
			if f := ev["fixed"]; f != "" {
				return f
			}
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// --- OSV JSON shape (the subset the owned store needs) ---

type osvDoc struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Upstream         []string       `json:"upstream"` // Rocky/RESF Apollo OSV names CVEs here, not in aliases
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Withdrawn        string         `json:"withdrawn"` // RFC3339 timestamp when the advisory was retracted; empty when active
	Severity         []osvSeverity  `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"` // GHSA/OSV carry a curated "severity" label here
	Affected         []osvAffected  `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges            []osvRange `json:"ranges"`
	Versions          []string   `json:"versions"`
	EcosystemSpecific struct {
		Imports []struct {
			Path    string   `json:"path"`
			Symbols []string `json:"symbols"`
		} `json:"imports"`
		// RustSec (crates.io) publishes affected functions as fully-qualified paths (crate::Type::method)
		// under ecosystem_specific.affects.functions; osv.dev re-exports them here.
		Affects struct {
			Functions []string `json:"functions"`
		} `json:"affects"`
	} `json:"ecosystem_specific"`
}

// osvImportSymbols collects the affected symbols an OSV entry carries. The Go vuln DB publishes them via
// affected[].ecosystem_specific.imports[].symbols (qualified as "importPath.Symbol" when a path is set);
// RustSec publishes them via affected[].ecosystem_specific.affects.functions as already-qualified
// "crate::Type::method" paths. Both feeds are read so the offline owned path carries the same affected
// symbols the reachability engine keys on, for every ecosystem that supplies them.
func osvImportSymbols(aff osvAffected) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, imp := range aff.EcosystemSpecific.Imports {
		for _, s := range imp.Symbols {
			if s == "" {
				continue
			}
			if imp.Path != "" {
				add(imp.Path + "." + s)
			} else {
				add(s)
			}
		}
	}
	for _, fn := range aff.EcosystemSpecific.Affects.Functions {
		add(fn) // already a fully-qualified crate::Type::method path
	}
	return out
}

type osvRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}
