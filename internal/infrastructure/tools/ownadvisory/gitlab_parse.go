package ownadvisory

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// gemnasiumEcosystem maps a GitLab gemnasium-db package_slug prefix to the OSV-canonical ecosystem the owned
// matcher keys on. An unmapped prefix is SKIPPED rather than guessed, so a component is never matched under a
// wrong ecosystem. The matcher is fail-closed for an ecosystem with no owned version comparator (it skips the
// range), so a mapped-but-uncomparable ecosystem cannot false-match either.
var gemnasiumEcosystem = map[string]string{
	"pypi":      "PyPI",
	"npm":       "npm",
	"maven":     "Maven",
	"gem":       "RubyGems",
	"nuget":     "NuGet",
	"packagist": "Packagist",
	"go":        "Go",
	"conan":     "ConanCenter",
	"pub":       "Pub",
}

// gemnasiumClause matches one constraint of a gemnasium affected_range group, e.g. ">= 1.2.0" or "==1.0.0".
// "==" is tried before "=" so an exact clause is not misread as ">=".
var gemnasiumClause = regexp.MustCompile(`^(>=|<=|==|=|<|>)\s*(.+)$`)

// gemnasiumAdvisory is the subset of a gemnasium-db YAML advisory the parser reads.
type gemnasiumAdvisory struct {
	Identifier    string   `yaml:"identifier"`
	Identifiers   []string `yaml:"identifiers"`
	PackageSlug   string   `yaml:"package_slug"`
	Title         string   `yaml:"title"`
	Description   string   `yaml:"description"`
	AffectedRange string   `yaml:"affected_range"`
	FixedVersions []string `yaml:"fixed_versions"`
	CVSSv3        string   `yaml:"cvss_v3"`
}

// ParseGemnasium converts one GitLab gemnasium-db YAML advisory into an owned advisory.Advisory. ok=false for
// a record with no identifier or no mappable affected package. Everything is derived from the record; an
// affected range that cannot be expressed soundly drops the package (a false negative is preferred to a wrong
// match), so the returned advisory only carries ranges the matcher can evaluate.
func ParseGemnasium(data []byte) (advisory.Advisory, bool) {
	var doc gemnasiumAdvisory
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return advisory.Advisory{}, false
	}
	id := strings.TrimSpace(doc.Identifier)
	if id == "" {
		return advisory.Advisory{}, false
	}
	eco, name, ok := splitGemnasiumSlug(doc.PackageSlug)
	if !ok {
		return advisory.Advisory{}, false
	}
	ranges, versions, ok := parseGemnasiumRange(doc.AffectedRange)
	if !ok || (len(ranges) == 0 && len(versions) == 0) {
		return advisory.Advisory{}, false
	}

	adv := advisory.Advisory{ID: id, Summary: strings.TrimSpace(doc.Title)}
	adv.CVSSVector = strings.TrimSpace(doc.CVSSv3)
	if adv.CVSSVector != "" {
		if score, ok := shared.CVSSBaseScore(adv.CVSSVector); ok {
			adv.CVSSScore = score
		}
	}
	aliasSet := map[string]struct{}{}
	for _, a := range doc.Identifiers {
		if a = strings.TrimSpace(a); a != "" && a != id {
			aliasSet[a] = struct{}{}
		}
	}
	for a := range aliasSet {
		adv.Aliases = append(adv.Aliases, a)
	}
	fixed := ""
	if len(doc.FixedVersions) > 0 {
		fixed = strings.TrimSpace(doc.FixedVersions[0])
	}
	adv.Affected = []advisory.AffectedPackage{{Ecosystem: eco, Package: name, FixedVersion: fixed, Ranges: ranges, Versions: versions}}
	return adv, true
}

// splitGemnasiumSlug splits "pypi/Django" into the OSV ecosystem and package name. An unmapped ecosystem
// prefix or a missing name returns ok=false.
func splitGemnasiumSlug(slug string) (ecosystem, name string, ok bool) {
	slug = strings.TrimSpace(slug)
	prefix, rest, found := strings.Cut(slug, "/")
	if !found {
		return "", "", false
	}
	eco, ok := gemnasiumEcosystem[strings.ToLower(strings.TrimSpace(prefix))]
	rest = strings.TrimSpace(rest)
	if !ok || rest == "" {
		return "", "", false
	}
	return eco, rest, true
}

// parseGemnasiumRange converts a gemnasium affected_range into owned ECOSYSTEM-type ranges plus exact
// versions. The range is a set of OR groups separated by "||"; within a group "," is AND. It is FP-safe: if
// ANY group cannot be expressed soundly (an exclusive lower bound, an unknown operator, an open-ended group,
// a contradictory group) the whole range returns ok=false so the caller drops the package rather than
// emitting a partial range that could match the wrong versions.
func parseGemnasiumRange(raw string) ([]advisory.Range, []string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil, false
	}
	var ranges []advisory.Range
	var versions []string
	for _, group := range strings.Split(raw, "||") {
		group = strings.TrimSpace(group)
		if group == "" {
			return nil, nil, false
		}
		var introduced, fixed, lastAffected, exact string
		var hasLower, hasUpper, hasExact bool
		for _, clause := range strings.Split(group, ",") {
			m := gemnasiumClause.FindStringSubmatch(strings.TrimSpace(clause))
			if m == nil {
				return nil, nil, false
			}
			op, ver := m[1], strings.TrimSpace(m[2])
			if ver == "" {
				return nil, nil, false
			}
			// A SECOND bound of the same side (two lower bounds, or two/mixed upper bounds) cannot be
			// resolved to the stricter one without the ecosystem comparator; overwriting one with the other
			// would over-broaden the range and match the wrong versions, so refuse the whole range instead.
			switch op {
			case ">=":
				if hasLower {
					return nil, nil, false
				}
				introduced, hasLower = ver, true
			case "<":
				if hasUpper {
					return nil, nil, false
				}
				fixed, hasUpper = ver, true
			case "<=":
				if hasUpper {
					return nil, nil, false
				}
				lastAffected, hasUpper = ver, true
			case "==", "=":
				if hasExact {
					return nil, nil, false
				}
				exact, hasExact = ver, true
			default: // ">" (exclusive lower bound) has no sound OSV equivalent; refuse rather than over-match
				return nil, nil, false
			}
		}
		switch {
		case exact != "":
			if introduced != "" || fixed != "" || lastAffected != "" {
				return nil, nil, false // "==V" combined with a bound is contradictory
			}
			versions = append(versions, exact)
		case fixed != "" || lastAffected != "":
			if introduced == "" {
				introduced = "0"
			}
			rng := advisory.Range{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: introduced}}}
			if fixed != "" {
				rng.Events = append(rng.Events, advisory.Event{Fixed: fixed})
			} else {
				rng.Events = append(rng.Events, advisory.Event{LastAffected: lastAffected})
			}
			ranges = append(ranges, rng)
		default:
			return nil, nil, false // an open-ended ">= X" group is not emitted
		}
	}
	return ranges, versions, true
}
