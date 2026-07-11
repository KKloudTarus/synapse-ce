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
	// Prefer a CVSS v3.x vector; compute the base score from it (the canonical band source).
	for _, sev := range doc.Severity {
		if strings.HasPrefix(sev.Type, "CVSS_V") && strings.HasPrefix(sev.Score, "CVSS:3.") {
			adv.CVSSVector = sev.Score
			if score, ok := shared.CVSSv3BaseScore(sev.Score); ok {
				adv.CVSSScore = score
			}
			break
		}
	}
	for _, aff := range doc.Affected {
		if aff.Package.Ecosystem == "" || aff.Package.Name == "" {
			continue // an advisory entry with no identifiable package can't be matched
		}
		adv.Affected = append(adv.Affected, advisory.AffectedPackage{
			Ecosystem: aff.Package.Ecosystem, // OSV ecosystem is the canonical form the matcher keys on
			// Normalize the package name to the ecosystem-canonical key (PEP 503 for PyPI) so the stored key
			// matches the SBOM-side lookup – OSV PyPI advisories carry non-normalized names ("Django").
			Package:      canonicalName(aff.Package.Ecosystem, aff.Package.Name),
			Ranges:       mapRanges(aff.Ranges),
			Versions:     aff.Versions,
			FixedVersion: firstFixed(aff.Ranges),
		})
	}
	return adv, nil
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
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
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
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}
