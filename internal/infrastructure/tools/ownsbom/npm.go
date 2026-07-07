package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// maxNPMNestDepth bounds the lockfileVersion-1 nested-dependencies recursion. Go's encoding/json already
// rejects JSON nested past ~10000 before Parse runs, but this makes the parser self-defending rather than
// leaning on that stdlib internal — a transitive tree deeper than this is malicious, so it fails loud.
const maxNPMNestDepth = 1000

// NPM is the owned npm-ecosystem parser (components + edges): it reads package-lock.json — the
// RESOLVED dependency tree — into npm components and, for lockfileVersion 2/3, the dependency edges between
// them. The modern lockfileVersion 2/3 `packages` map (flat, keyed by install path, carrying a `dev` flag
// + the dependency ranges) is the primary source; lockfileVersion 1's nested `dependencies` map is recursed
// as a fallback (COMPONENTS ONLY — v1 edge resolution over the nested tree is a legacy-format follow-up;
// v1 is npm <7, pre-2020). Resolved versions AND the dev/prod scope come straight from the lock, so no
// companion package.json read is needed. Pure JSON parsing, no third-party library, vendor-neutral.
//
// Limitation (honest deferral): a LOCAL workspace/`link` package in a monorepo (a bare non-node_modules
// path like "packages/lib", plus its versionless "link": true symlink entry under node_modules) is not
// emitted as a component — so its outgoing edges are omitted too. This matches the workspace-blind
// convention of the yarn parser + the Syft path; precise monorepo workspace edges are a follow-up.
type NPM struct{}

// Ecosystem identifies this parser's package ecosystem.
func (NPM) Ecosystem() string { return "npm" }

// Markers are the lockfile basenames NPM claims.
func (NPM) Markers() []string { return []string{"package-lock.json"} }

// npmV1Dep is a node in the lockfileVersion-1 nested `dependencies` tree.
type npmV1Dep struct {
	Version      string              `json:"version"`
	Dev          bool                `json:"dev"`
	Integrity    string              `json:"integrity"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

// npmV3Pkg is one entry in the lockfileVersion-2/3 flat `packages` map (keyed by install path). The
// dependency-range maps name this package's direct deps; the RESOLVED version of each is found by walking
// the install path (npm's hoisting — see resolveNpmDep), not from these ranges.
type npmV3Pkg struct {
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Integrity            string            `json:"integrity"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// Parse extracts the resolved npm packages (+ v2/v3 edges) from a package-lock.json.
func (NPM) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	var lock struct {
		Packages     map[string]npmV3Pkg `json:"packages"`
		Dependencies map[string]npmV1Dep `json:"dependencies"`
	}
	if err := json.Unmarshal(in.Content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	prodScope := sbom.ClassifyScope(in.Path, "") // production, unless the lock sits under examples/test/etc.
	set := newComponentSet()
	npmPURL := func(name, version string) string {
		// PURL spec: a scoped package @scope/name carries the leading @ percent-encoded as %40 (matches the
		// Syft path + the PURL conformance test), while Component.Name keeps the @scope/name.
		purlName := name
		if strings.HasPrefix(purlName, "@") {
			purlName = "%40" + purlName[1:]
		}
		return "pkg:npm/" + purlName + "@" + version
	}
	add := func(name, version, integrity string, dev bool) string {
		name = strings.TrimSpace(name)
		scope := prodScope
		if dev {
			scope = sbom.ScopeDevelopment
		}
		purl := npmPURL(name, version)
		set.add(sbom.Component{Name: name, Version: version, PURL: purl, Location: in.Path, Scope: scope, Checksums: parseSubresourceIntegrity(integrity)})
		return purl
	}

	if len(lock.Packages) > 0 { // lockfileVersion 2/3 — flat + complete
		// Pass 1: emit components + index install-path -> PURL (the root project, path "", is not a dep).
		pathPURL := make(map[string]string, len(lock.Packages))
		for path, p := range lock.Packages {
			if name := npmNameFromPath(path); name != "" {
				pathPURL[path] = add(name, p.Version, p.Integrity, p.Dev)
			}
		}
		// Pass 2: resolve each package's direct deps to PURLs via npm's nearest-wins hoisting. Deterministic:
		// iterate paths + dep names sorted. Resolution-as-filter — a dep not present in the tree yields no edge.
		paths := make([]string, 0, len(lock.Packages))
		for path := range lock.Packages {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		var edges []sbom.Dependency
		for _, path := range paths {
			ref, ok := pathPURL[path]
			if !ok {
				continue // root project / unnamed — not a component, so no edges from it
			}
			seen := map[string]bool{ref: true} // drop self-edges + duplicate targets
			var on []string
			for _, depName := range npmDepNames(lock.Packages[path]) {
				tp := resolveNpmDep(path, depName, lock.Packages)
				if tp == "" {
					continue
				}
				if t := pathPURL[tp]; t != "" && !seen[t] {
					seen[t] = true
					on = append(on, t)
				}
			}
			if len(on) > 0 {
				edges = append(edges, sbom.Dependency{Ref: ref, DependsOn: on})
			}
		}
		return set.components(), edges, nil
	}

	// lockfileVersion 1 — recurse the nested dependencies map (components only; v1 edges are a legacy follow-up).
	var walk func(deps map[string]npmV1Dep, depth int) error
	walk = func(deps map[string]npmV1Dep, depth int) error {
		if depth > maxNPMNestDepth {
			return fmt.Errorf("%w: package-lock.json nesting exceeds %d levels", shared.ErrValidation, maxNPMNestDepth)
		}
		for name, d := range deps {
			add(name, d.Version, d.Integrity, d.Dev)
			if err := walk(d.Dependencies, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(lock.Dependencies, 0); err != nil {
		return nil, nil, err
	}
	return set.components(), nil, nil
}

// parseSubresourceIntegrity parses a W3C Subresource Integrity string as npm/yarn/pnpm record it in a
// lockfile `integrity` field: one or more space-separated "<alg>-<base64>" hashes (e.g.
// "sha512-<b64> sha1-<b64>"). Each becomes a Checksum with an SPDX-style uppercased algorithm name and the
// base64 digest as recorded. Malformed tokens are skipped; returns nil when none parse.
func parseSubresourceIntegrity(s string) []sbom.Checksum {
	var out []sbom.Checksum
	for _, tok := range strings.Fields(s) {
		i := strings.IndexByte(tok, '-')
		if i <= 0 || i == len(tok)-1 {
			continue // not the "<alg>-<digest>" shape
		}
		out = append(out, sbom.Checksum{Algorithm: strings.ToUpper(tok[:i]), Value: tok[i+1:]})
	}
	return out
}

// npmDepNames returns the sorted, unique direct-dependency names of a v2/v3 package: its dependencies +
// devDependencies (chiefly on the root, but npm may write them on nested entries too) + optionalDependencies
// — i.e. everything npm installs into the tree for it. peerDependencies are excluded (a "the host must
// provide" expectation, not a "this depends on").
func npmDepNames(p npmV3Pkg) []string {
	set := map[string]bool{}
	for _, m := range []map[string]string{p.Dependencies, p.DevDependencies, p.OptionalDependencies} {
		for name := range m {
			set[name] = true
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// resolveNpmDep resolves dependency depName, as required by the package installed at fromPath, to the
// install path of the package that satisfies it — npm's hoisting rule: search fromPath's own
// node_modules first, then each ancestor install context outward, ending at the root node_modules; the
// nearest match wins. Returns "" when no installed package satisfies it (resolution-as-filter → no edge).
func resolveNpmDep(fromPath, depName string, packages map[string]npmV3Pkg) string {
	cur := fromPath
	for {
		cand := "node_modules/" + depName
		if cur != "" {
			cand = cur + "/node_modules/" + depName
		}
		if _, ok := packages[cand]; ok {
			return cand
		}
		if cur == "" {
			return "" // already tried the root node_modules — unresolvable
		}
		if idx := strings.LastIndex(cur, "/node_modules/"); idx >= 0 {
			cur = cur[:idx] // step out to the parent install context
		} else {
			cur = "" // cur was a root-level node_modules/<pkg>; next iteration tries the root
		}
	}
}

// npmNameFromPath turns a lockfileVersion-2/3 `packages` key into a package name: "node_modules/foo" ->
// "foo", "node_modules/@scope/bar" -> "@scope/bar", a nested ".../node_modules/b" -> "b" (the last
// segment). The root-project key "" yields "" (skipped — the project itself is not a dependency).
func npmNameFromPath(p string) string {
	const nm = "node_modules/"
	i := strings.LastIndex(p, nm)
	if i < 0 {
		return ""
	}
	return p[i+len(nm):]
}
