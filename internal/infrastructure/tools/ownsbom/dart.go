package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Dart is the owned Dart/Flutter parser: it reads pubspec.lock – the resolved package set –
// into pub components. pubspec.lock is YAML; under the `packages:` map each indent-2 key is a package whose
// indent-4 fields include `version:` and `dependency:` ("direct dev" ⇒ development scope, else production).
// Hand-parsed (a small indented subset – no YAML library, vendor-neutral); deeper-indented `description:`
// sub-maps are ignored by matching fields at EXACTLY indent 4.
//
// pubspec.lock records NO inter-package edges (only a per-package `dependency:` direct/transitive flag), so
// the resolved transitive tree is not recoverable from the lockfile alone. The strongest sound edges come
// from the companion pubspec.yaml (`in.Dir`): the project root and its declared direct `dependencies:` /
// `dev_dependencies:` (with ranges). Those root→direct edges are emitted when the companion is present;
// transitive edges are deliberately NOT synthesized (documented limitation, EPIC #1034 no-fabrication bar).
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
		trimmed := strings.TrimSpace(stripInlineComment(raw))
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

	// Edges: root→direct from the companion pubspec.yaml. Only edges whose target is a resolved lock package
	// are kept (an SDK pseudo-dep like `flutter` is not a pub.dev component and is skipped).
	lockIndex := map[string]string{} // package name → PURL, from the resolved lock components above
	for _, c := range comps {
		lockIndex[c.Name] = c.PURL
	}
	deps := dartRootEdges(in.Dir, lockIndex, baseScope)
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return comps, deps, nil
}

// dartRootEdges reads the companion pubspec.yaml and returns root→direct-dependency edges. The project root
// is a SYNTHETIC graph node (not added as a component): sbom.IsDirect deliberately treats a non-component
// dependent as a project root, so a direct dependency stays direct. It returns no edges when the manifest is
// absent, unnamed, or names no resolvable direct dependency (never fabricating a root or an edge).
func dartRootEdges(dir string, lockIndex map[string]string, baseScope string) []sbom.Dependency {
	if dir == "" {
		return nil
	}
	content, ok := readManifestFile(filepath.Join(dir, "pubspec.yaml"))
	if !ok {
		return nil
	}
	var projName, projVersion string
	section := "" // "dependencies" | "dev_dependencies" | ""
	prodByTarget, devByTarget := map[string]string{}, map[string]string{}
	var prod, dev []string
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(stripInlineComment(raw))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			section = ""
			if n, ok := yamlScalar(trimmed, "name:"); ok {
				projName = n
			} else if v, ok := yamlScalar(trimmed, "version:"); ok {
				projVersion = v
			} else if trimmed == "dependencies:" {
				section = "dependencies"
			} else if trimmed == "dev_dependencies:" {
				section = "dev_dependencies"
			}
			continue
		}
		if section == "" || indent != 2 || !strings.Contains(trimmed, ":") {
			continue // only indent-2 `name: constraint` (or `name:` map) entries under a deps section
		}
		kv := strings.SplitN(trimmed, ":", 2)
		key := strings.TrimSpace(kv[0])
		rng := strings.Trim(strings.TrimSpace(kv[1]), `"'`) // "" when the value is a nested map (sdk/git dep)
		t, resolved := lockIndex[key]
		if !resolved {
			continue // an unresolved dep (sdk pseudo, path/git, or absent from the lock) is not a sound edge
		}
		if section == "dependencies" {
			prod = append(prod, t)
			if rng != "" {
				prodByTarget[t] = rng
			}
		} else {
			dev = append(dev, t)
			if rng != "" {
				devByTarget[t] = rng
			}
		}
	}
	if projName == "" || (len(prod) == 0 && len(dev) == 0) {
		return nil // no named root, or nothing resolvable to depend on
	}
	root := "pkg:pub/" + projName
	if projVersion != "" {
		root += "@" + projVersion
	}
	var edges []sbom.Dependency
	if len(prod) > 0 {
		sort.Strings(prod)
		edges = append(edges, sbom.Dependency{Ref: root, DependsOn: prod, Scope: baseScope, RequestedRanges: rangesFor(prod, prodByTarget)})
	}
	if len(dev) > 0 {
		sort.Strings(dev)
		edges = append(edges, sbom.Dependency{Ref: root, DependsOn: dev, Scope: sbom.ScopeDevelopment, RequestedRanges: rangesFor(dev, devByTarget)})
	}
	return edges
}

// yamlScalar extracts a scalar value for a `key:` line (e.g. `version: "0.13.5"` → `0.13.5`), stripping
// surrounding quotes. ok=false when the line is not that key.
func yamlScalar(line, key string) (string, bool) {
	if !strings.HasPrefix(line, key) {
		return "", false
	}
	return strings.Trim(strings.TrimSpace(line[len(key):]), `"'`), true
}
