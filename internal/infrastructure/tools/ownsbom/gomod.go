package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// GoMod is the owned Go-ecosystem parser: it reads go.mod `require` directives – both the
// block form `require (…)` and the single-line `require <path> <version>` – into golang components,
// dropping the trailing `// indirect` comment. go.mod alone carries no full edge graph (that needs
// `go mod graph`), so this emits components only – the dependency graph + direct/
// transitive proof come later. Hand-parsed (no third-party module library) to keep the producer
// vendor-neutral and dependency-light.
type GoMod struct{}

// Ecosystem identifies this parser's package ecosystem.
func (GoMod) Ecosystem() string { return "go" }

// Markers are the manifest basenames GoMod claims.
func (GoMod) Markers() []string { return []string{"go.mod"} }

// Parse extracts the required modules from a go.mod file as golang components (PURL pkg:golang/path@ver),
// each scoped/located from the manifest path so background-vs-production ranking matches the Syft path.
func (GoMod) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	// All modules declared in one go.mod share its on-disk location and derived scope (e.g. a go.mod under
	// examples/ or testdata/ is background); ClassifyScope handles the directory heuristics.
	scope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	inBlock := false
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "//"):
			continue
		case strings.HasPrefix(line, "require ("):
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case strings.HasPrefix(line, "require "): // single-line require
			addModule(strings.TrimPrefix(line, "require "), in.Path, scope, set)
		case inBlock:
			addModule(line, in.Path, scope, set)
			// module / go / toolchain / replace / exclude / retract lines fall through and are ignored
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan go.mod: %w", err)
	}
	return set.components(), nil, nil
}

// addModule parses one `<path> <version> [// indirect]` requirement and records a golang component
// carrying the manifest location + scope (the set dedups by PURL).
func addModule(line, location, scope string, set *componentSet) {
	if i := strings.Index(line, "//"); i >= 0 {
		line = strings.TrimSpace(line[:i]) // drop the trailing comment (e.g. "// indirect")
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return
	}
	path, version := f[0], f[1]
	// go.mod module versions are canonical semver, always "v"-prefixed (incl. pseudo-versions +
	// +incompatible); this also filters any non-require line that slips through.
	if path == "" || !strings.HasPrefix(version, "v") {
		return
	}
	set.add(sbom.Component{Name: path, Version: version, PURL: "pkg:golang/" + path + "@" + version, Location: location, Scope: scope})
}
