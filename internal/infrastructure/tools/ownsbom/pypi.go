package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// PyPI is the owned Python parser: it reads pip requirements files, extracting PINNED
// `name==version` requirements as pypi components. Only `==`/`===` pins yield a resolved version (an SBOM
// needs resolved versions, so unpinned ranges >=/~=/etc. are skipped – they can't soundly match an
// advisory). It handles comments (#), nested includes + option lines (-r/-c/-e/--hash), environment
// markers (`; python_version<…`), and extras (`pkg[extra]`). The dev/prod scope is derived from the file
// PATH (requirements-dev.txt -> development) via ClassifyScope. Names are PEP 503-normalized for the PURL.
// Hand-parsed, no third-party library, vendor-neutral.
type PyPI struct{}

// Ecosystem identifies this parser's package ecosystem.
func (PyPI) Ecosystem() string { return "pypi" }

// Markers are the requirements-file basenames PyPI claims. (Globbed requirements/*.txt is a follow-up;
// the contract dispatches by basename today.)
func (PyPI) Markers() []string { return []string{"requirements.txt", "requirements-dev.txt"} }

var pep503Sep = regexp.MustCompile(`[-_.]+`)

// normalizePyPI applies PEP 503 normalization: lower-case + collapse runs of -, _,. to a single -, so
// the PURL matches what the registry/advisory feeds key on (PyPI names are case- + separator-insensitive).
func normalizePyPI(name string) string {
	return strings.ToLower(pep503Sep.ReplaceAllString(name, "-"))
}

// Parse extracts pinned requirements from a pip requirements file as pypi components.
func (PyPI) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	scope := sbom.ClassifyScope(in.Path, "") // requirements-dev.txt -> development; others -> production/path-derived
	set := newComponentSet()
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 { // strip a comment (whole-line or trailing)
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "-") { // blank, or an option/include line (-r, -c, -e, --hash)
			continue
		}
		if i := strings.IndexByte(line, ';'); i >= 0 { // drop an environment marker (; python_version<"3.8")
			line = strings.TrimSpace(line[:i])
		}
		eq := strings.Index(line, "==") // only an == / === pin gives a resolved version
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(line[:eq])
		if b := strings.IndexByte(name, '['); b >= 0 { // strip extras: pkg[extra1,extra2]
			name = strings.TrimSpace(name[:b])
		}
		// Trim all leading '=' (the 3rd '=' of an arbitrary-equality `===`, possibly space-separated) then
		// re-trim the space PEP 440 allows around the operator, before cutting at any trailing option/specifier.
		version := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(line[eq+2:]), "="))
		if j := strings.IndexAny(version, " \t,"); j >= 0 { // stop at a trailing option / compound specifier
			version = version[:j]
		}
		if name == "" || !sbom.IsResolvedVersion(version) {
			continue
		}
		name = normalizePyPI(name)
		set.add(sbom.Component{Name: name, Version: version, PURL: "pkg:pypi/" + name + "@" + version, Location: in.Path, Scope: scope})
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan requirements: %w", err)
	}
	return set.components(), nil, nil
}
