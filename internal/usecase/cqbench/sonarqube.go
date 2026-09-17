package cqbench

import (
	"io"
	"sort"
	"strings"
)

// SonarQubeExport is the flat, tool-neutral shape the CI baseline step reduces SonarQube CE's two endpoints
// (/api/issues/search for bugs/vulnerabilities/code smells and /api/hotspots/search for security hotspots)
// into: one list of located issues, each carrying a SonarQube issue type. Keeping the reducer's input this
// simple means the SonarQube-version-specific API shape lives in the workflow, not in this pinned reducer.
type SonarQubeExport struct {
	Issues []SonarQubeIssue `json:"issues"`
}

// SonarQubeIssue is one located SonarQube finding. Component is SonarQube's "projectKey:path/within/project"
// identifier; Type is one of BUG, VULNERABILITY, CODE_SMELL, SECURITY_HOTSPOT.
type SonarQubeIssue struct {
	Component string `json:"component"`
	Line      int    `json:"line"`
	Type      string `json:"type"`
	Rule      string `json:"rule,omitempty"`
}

// SonarQubeObservations reduces a SonarQube CE export into one observation per corpus case, so the SonarQube
// baseline is scored by the exact same reducer as the owned engine. The scanner is assumed to have run over a
// project whose top-level directories are the corpus fixtures, so a component path "py-smells/sample.py" maps
// to the case whose Fixture is "py-smells" and the fixture-relative file "sample.py". Every corpus case
// receives an observation (empty when SonarQube found nothing in that fixture), so a fixture SonarQube did not
// flag lowers its recall rather than dropping out of the denominator. An issue outside any corpus fixture, or
// with no line, is ignored.
func SonarQubeObservations(corpus Corpus, r io.Reader) ([]CaseObservation, error) {
	if err := validateCorpus(corpus); err != nil {
		return nil, err
	}
	export, err := decodeSonarQube(r)
	if err != nil {
		return nil, err
	}
	// validateCorpus (above) has already rejected two cases sharing a fixture dir, so this map is one-to-one.
	fixtureToCase := make(map[string]string, len(corpus.Cases))
	for _, c := range corpus.Cases {
		fixtureToCase[c.Fixture] = c.Name
	}
	issuesByCase := make(map[string][]Issue, len(corpus.Cases))
	for _, iss := range export.Issues {
		if iss.Line < 1 {
			continue // a file-level issue has no line to match a labelled location
		}
		t, ok := sonarType(iss.Type)
		if !ok {
			continue // an unknown SonarQube type is not on the shared axis
		}
		fixture, file, ok := splitComponent(iss.Component)
		if !ok {
			continue
		}
		caseName, ok := fixtureToCase[fixture]
		if !ok {
			continue // an issue outside any corpus fixture
		}
		issuesByCase[caseName] = append(issuesByCase[caseName], Issue{File: file, Line: iss.Line, Type: t})
	}
	out := make([]CaseObservation, 0, len(corpus.Cases))
	for _, c := range corpus.Cases {
		issues := issuesByCase[c.Name]
		sort.Slice(issues, func(i, j int) bool {
			if issues[i].File != issues[j].File {
				return issues[i].File < issues[j].File
			}
			if issues[i].Line != issues[j].Line {
				return issues[i].Line < issues[j].Line
			}
			return issues[i].Type < issues[j].Type
		})
		out = append(out, CaseObservation{Case: c.Name, Issues: issues})
	}
	return out, nil
}

func decodeSonarQube(r io.Reader) (SonarQubeExport, error) {
	var export SonarQubeExport
	if err := decodeStrict(r, &export, "sonarqube export"); err != nil {
		return SonarQubeExport{}, err
	}
	return export, nil
}

// sonarType maps a SonarQube issue type onto the shared axis.
func sonarType(t string) (IssueType, bool) {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "BUG":
		return TypeBug, true
	case "VULNERABILITY":
		return TypeVulnerability, true
	case "CODE_SMELL":
		return TypeCodeSmell, true
	case "SECURITY_HOTSPOT":
		return TypeSecurityHotspot, true
	default:
		return "", false
	}
}

// splitComponent turns a SonarQube component id ("projectKey:fixture/file") into (fixture, fixture-relative
// file). The path is everything after the first colon; its first segment is the fixture dir.
func splitComponent(component string) (fixture, file string, ok bool) {
	path := component
	if i := strings.IndexByte(component, ':'); i >= 0 {
		path = component[i+1:]
	}
	path = strings.TrimPrefix(strings.TrimSpace(path), "./")
	if path == "" {
		return "", "", false
	}
	seg := strings.SplitN(path, "/", 2)
	if len(seg) != 2 || seg[0] == "" || seg[1] == "" {
		return "", "", false // a project-root or fixture-root component names no file to match
	}
	return seg[0], seg[1], true
}
