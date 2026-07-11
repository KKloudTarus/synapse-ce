package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Dart is the owned Dart/Flutter parser: it reads pubspec.lock – the resolved package set –
// into pub components. pubspec.lock is YAML; under the `packages:` map each indent-2 key is a package whose
// indent-4 fields include `version:` and `dependency:` ("direct dev" ⇒ development scope, else production).
// Hand-parsed (a small indented subset – no YAML library, vendor-neutral); deeper-indented `description:`
// sub-maps are ignored by matching fields at EXACTLY indent 4. Components only – edges deferred.
type Dart struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Dart) Ecosystem() string { return "pub" }

// Markers are the lockfile basenames Dart claims.
func (Dart) Markers() []string { return []string{"pubspec.lock"} }

// Parse extracts the resolved pub packages from the `packages:` map. Each indent-2 `name:` key starts a
// package; its indent-4 `version:`/`dependency:` fields set the version + scope. A new top-level section
// (indent 0, e.g. `sdks:`) ends the packages block. Sorted by PURL for determinism.
func (Dart) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	baseScope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()

	inPackages := false
	var name, version, source string
	dev := false
	flush := func() {
		// Skip SDK pseudo-packages (flutter, flutter_test, sky_engine, …): `pub` emits them with
		// source: sdk + version "0.0.0"; they are not pub.dev registry packages, so emitting them would be a
		// phantom component (mirrors NuGet's Project-ref skip + Yarn's workspace skip).
		if name != "" && version != "" && source != "sdk" {
			scope := baseScope
			if dev {
				scope = sbom.ScopeDevelopment
			}
			set.add(sbom.Component{Name: name, Version: version, PURL: "pkg:pub/" + name + "@" + version, Location: in.Path, Scope: scope})
		}
		name, version, source, dev = "", "", "", false
	}

	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		switch {
		case indent == 0: // a new top-level section ends the packages block (and any in-progress package)
			flush()
			inPackages = trimmed == "packages:"
		case inPackages && indent == 2 && strings.HasSuffix(trimmed, ":"):
			flush() // a new package key
			name = strings.TrimSuffix(trimmed, ":")
		case inPackages && indent == 4 && name != "": // direct fields only (indent-6 description sub-map ignored)
			if v, ok := yamlScalar(trimmed, "version:"); ok {
				version = v
			} else if d, ok := yamlScalar(trimmed, "dependency:"); ok {
				dev = strings.Contains(d, "dev") // "direct dev" ⇒ dev; "direct main"/"transitive" ⇒ prod
			} else if s, ok := yamlScalar(trimmed, "source:"); ok {
				source = s // "sdk" ⇒ a Flutter SDK pseudo-package, dropped in flush()
			}
		}
	}
	flush() // the final package
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan pubspec.lock: %w", err)
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, nil, nil
}

// yamlScalar extracts a scalar value for a `key:` line (e.g. `version: "0.13.5"` → `0.13.5`), stripping
// surrounding quotes. ok=false when the line is not that key.
func yamlScalar(line, key string) (string, bool) {
	if !strings.HasPrefix(line, key) {
		return "", false
	}
	return strings.Trim(strings.TrimSpace(line[len(key):]), `"'`), true
}
