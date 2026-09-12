// Package accuracyeval loads an embedded golden corpus of labeled detection cases and reduces the
// owned engine's produced-vs-expected results to detection-accuracy metrics (precision, recall,
// false-discovery / false-negative rates), overall and per ecosystem group. The engine itself is
// injected as a CaseScanner so this stays in the usecase layer (domain + benchmark only, no
// infrastructure). The SCA golden gate and the nightly worker job both consume this loader, so the
// measured and gated corpora can never drift apart.
package accuracyeval

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// CorpusVersion identifies the embedded golden corpus. Bump it when the corpus set changes so a
// persisted accuracy run records which corpus produced it.
const CorpusVersion = "detection-golden-v1"

//go:embed corpus/*.json
var corpusFS embed.FS

// Range is one version range on an affected package in a corpus advisory.
type Range struct {
	Type         string `json:"type"` // SEMVER | ECOSYSTEM | GIT
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Advisory is a compact, authorable advisory record pinned into a case.
type Advisory struct {
	ID         string   `json:"id"`
	Aliases    []string `json:"aliases,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	CVSSScore  float64  `json:"cvss_score,omitempty"`
	CVSSVector string   `json:"cvss_vector,omitempty"`
	Ecosystem  string   `json:"ecosystem"` // OSV ecosystem / distro key (e.g. "npm", "PyPI", "Debian:11")
	Package    string   `json:"package"`
	Ranges     []Range  `json:"ranges,omitempty"`
	Versions   []string `json:"versions,omitempty"`
	Fixed      string   `json:"fixed_version,omitempty"`
	Withdrawn  bool     `json:"withdrawn,omitempty"`
}

// Component is one SBOM component in a case.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// Expected is one ground-truth detection that MUST be produced, keyed to a specific component
// VERSION so a false positive on a patched version of the same package is not masked by a true
// positive on the vulnerable version. CVE is the advisory id the source is expected to REPORT.
type Expected struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	CVE       string `json:"cve"`
}

// Case is one labeled evaluation unit.
type Case struct {
	Name       string      `json:"name"`
	Group      string      `json:"group"` // ecosystem, for the per-group ratchet
	Notes      string      `json:"notes,omitempty"`
	Components []Component `json:"components"`
	Advisories []Advisory  `json:"advisories"`
	Expected   []Expected  `json:"expected"`
}

// Load reads and validates every case in the embedded corpus, sorted by name, rejecting unknown
// fields and duplicate case names.
func Load() ([]Case, error) {
	entries, err := corpusFS.ReadDir("corpus")
	if err != nil {
		return nil, fmt.Errorf("read corpus dir: %w", err)
	}
	var cases []Case
	names := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := corpusFS.ReadFile("corpus/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		var fileCases []Case
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fileCases); err != nil {
			return nil, fmt.Errorf("decode %s: %w", e.Name(), err)
		}
		for _, c := range fileCases {
			if names[c.Name] {
				return nil, fmt.Errorf("duplicate case name %q (in %s)", c.Name, e.Name())
			}
			names[c.Name] = true
			cases = append(cases, c)
		}
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })
	if len(cases) == 0 {
		return nil, fmt.Errorf("no corpus cases loaded")
	}
	return cases, nil
}

// CaseAdvisories converts a case's pinned corpus advisories into domain advisories, the input a
// CaseScanner runs the owned engine against.
func CaseAdvisories(c Case) []advisory.Advisory {
	out := make([]advisory.Advisory, 0, len(c.Advisories))
	for _, a := range c.Advisories {
		ranges := make([]advisory.Range, 0, len(a.Ranges))
		for _, r := range a.Ranges {
			events := make([]advisory.Event, 0, 3)
			if r.Introduced != "" {
				events = append(events, advisory.Event{Introduced: r.Introduced})
			}
			if r.Fixed != "" {
				events = append(events, advisory.Event{Fixed: r.Fixed})
			}
			if r.LastAffected != "" {
				events = append(events, advisory.Event{LastAffected: r.LastAffected})
			}
			ranges = append(ranges, advisory.Range{Type: r.Type, Events: events})
		}
		out = append(out, advisory.Advisory{
			ID: a.ID, Aliases: a.Aliases, Summary: a.Summary, CVSSScore: a.CVSSScore, CVSSVector: a.CVSSVector,
			Withdrawn: a.Withdrawn,
			Affected: []advisory.AffectedPackage{{
				Ecosystem: a.Ecosystem, Package: a.Package, Ranges: ranges, Versions: a.Versions, FixedVersion: a.Fixed,
			}},
		})
	}
	return out
}

// CaseSBOM converts a case's components into an SBOM document for the owned engine.
func CaseSBOM(c Case) *sbom.SBOM {
	doc := &sbom.SBOM{}
	for _, comp := range c.Components {
		doc.Components = append(doc.Components, sbom.Component{Name: comp.Name, Version: comp.Version, PURL: comp.PURL})
	}
	return doc
}
