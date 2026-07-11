package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Yarn is the owned parser for yarn.lock (components + edges) – npm-ecosystem packages resolved
// by Yarn. It line-parses the lock's entries: a key line of one-or-more `name@range` descriptors, an
// indented `version "x.y.z"` (Yarn v1) / `version: x.y.z` (Yarn Berry) giving the resolved version, and an
// optional indented `dependencies:` block of `name range` direct deps. yarn.lock carries no dev flag, so it
// reads the companion package.json (via ParseInput.Dir) and scopes its [devDependencies] as development.
//
// Edges: yarn.lock is effectively a DESCRIPTOR→version map – each entry's key line lists every `name@range`
// descriptor that resolves to it. So a dependency `name range` is resolved by reconstructing its descriptor
// (`name@range`) and looking up the entry that claims it (resolution-as-filter: an unclaimed descriptor –
// e.g. a workspace/peer dep with no lock entry – yields no edge). No nearest-wins is needed (yarn's lock is
// already a flat descriptor map, unlike npm's path-keyed tree). Hand-parsed, no third-party lib.
type Yarn struct{}

// Ecosystem identifies this parser's package ecosystem (Yarn resolves npm packages).
func (Yarn) Ecosystem() string { return "npm" }

// Markers are the lockfile basenames Yarn claims.
func (Yarn) Markers() []string { return []string{"yarn.lock"} }

// yarnEntry is one lock entry collected in pass 1: its resolved name+version, the descriptors its key line
// claims (for edge resolution), and the direct deps from its dependencies: block.
type yarnEntry struct {
	name, version string
	integrity     string    // the `integrity` Subresource Integrity value (Yarn v1), when present
	descriptors   []string  // full `name@range` specs from the key line(s)
	deps          []yarnDep // direct deps from the dependencies: block
}

type yarnDep struct{ name, rng string }

// Parse extracts the resolved packages + dependency edges from a yarn.lock.
func (Yarn) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil { // honor cancellation before the companion read
		return nil, nil, err
	}
	devNames := npmDevDeps(in.Dir) // [devDependencies] from the companion package.json (best-effort)
	prodScope := sbom.ClassifyScope(in.Path, "")

	// Pass 1: collect entries (identity + descriptors + dependency block).
	var entries []*yarnEntry
	var cur *yarnEntry
	inDeps := false
	depsIndent := 0
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !indented(raw) {
			// a col-0 key line starts a new entry. A `name@workspace:…` key is the project/workspace ITSELF
			// (its version is the non-matchable 0.0.0-use.local), not a dependency – skip it; a non-spec line
			// (Berry's __metadata) has no name and is skipped too.
			inDeps, cur = false, nil
			if strings.HasSuffix(line, ":") && !strings.Contains(line, "@workspace:") {
				if descs, name := yarnDescriptors(line); name != "" {
					cur = &yarnEntry{name: name, descriptors: descs}
					entries = append(entries, cur)
				}
			}
			continue
		}
		if cur == nil {
			continue // inside a skipped entry (__metadata / workspace root)
		}
		indent := leadingIndent(raw)
		if inDeps {
			if indent > depsIndent { // a member of the dependencies: block (more indented than it)
				if d, ok := parseYarnDep(line); ok {
					cur.deps = append(cur.deps, d)
				}
				continue
			}
			inDeps = false // dedented back to an entry field – the dependencies: block ended
		}
		switch {
		case strings.HasPrefix(line, "dependencies:") || strings.HasPrefix(line, "optionalDependencies:"):
			// Both are real installed edges (optional ones are present in the tree when satisfiable; an
			// unsatisfied one fails the descriptor lookup → no edge anyway) – parity with the npm parser,
			// which also merges optionalDependencies. peerDependencies stays excluded (host-provides).
			inDeps, depsIndent = true, indent
		case strings.HasPrefix(line, "version ") || strings.HasPrefix(line, "version:"):
			cur.version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version")), `:" `)
		case strings.HasPrefix(line, "integrity "):
			// Yarn v1 records a Subresource Integrity value ("integrity sha512-<b64>"); Yarn Berry's
			// `checksum:` is an internal cache hash, not an artifact digest, so it is intentionally not captured.
			cur.integrity = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "integrity")), `:" `)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan yarn.lock: %w", err)
	}

	// Index every claimed descriptor -> resolved version (the lock's descriptor map).
	descVer := make(map[string]string)
	for _, e := range entries {
		if e.version == "" {
			continue
		}
		for _, d := range e.descriptors {
			descVer[d] = e.version
		}
	}

	// Pass 2: emit components + resolve edges via the descriptor map.
	set := newComponentSet()
	var edges []sbom.Dependency
	for _, e := range entries {
		if e.version == "" {
			continue // no resolved version (e.g. a malformed entry) – not a component
		}
		scope := prodScope
		if devNames[e.name] {
			scope = sbom.ScopeDevelopment
		}
		ref := yarnPURL(e.name, e.version)
		set.add(sbom.Component{Name: e.name, Version: e.version, PURL: ref, Location: in.Path, Scope: scope, Checksums: parseSubresourceIntegrity(e.integrity)})
		seen := map[string]bool{ref: true} // drop self-edges + duplicate targets
		var on []string
		for _, d := range e.deps {
			v, ok := descVer[d.name+"@"+d.rng]
			if !ok {
				continue // descriptor not claimed by any lock entry – no edge
			}
			if t := yarnPURL(d.name, v); !seen[t] {
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

// yarnPURL builds the npm PURL for a package, percent-encoding a scoped name's leading @ as %40 (PURL spec,
// matching the package-lock parser).
func yarnPURL(name, version string) string {
	purlName := name
	if strings.HasPrefix(purlName, "@") {
		purlName = "%40" + purlName[1:]
	}
	return "pkg:npm/" + purlName + "@" + version
}

// indented reports whether a raw line begins with whitespace (a field within a yarn.lock entry, vs a
// top-level key line).
func indented(raw string) bool {
	return strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")
}

// leadingIndent counts a line's leading whitespace (space OR tab) to tell a dependencies: block member
// (more indented) from a sibling entry field. It counts tabs as well as spaces so it agrees with indented()
// – yarn.lock is 2-space by spec, but a tab-indented file must not silently lose every edge.
func leadingIndent(raw string) int {
	n := 0
	for n < len(raw) && (raw[n] == ' ' || raw[n] == '\t') {
		n++
	}
	return n
}

// yarnDescriptors splits a yarn.lock key line into its full `name@range` descriptors (comma-separated,
// quote-trimmed) and returns them plus the entry's package name (from the first descriptor). A key with no
// real spec (e.g. __metadata) returns ("", nil).
func yarnDescriptors(keyLine string) ([]string, string) {
	key := strings.TrimSuffix(strings.TrimSpace(keyLine), ":")
	var descs []string
	for _, part := range strings.Split(key, ",") {
		if d := strings.Trim(strings.TrimSpace(part), `"`); d != "" {
			descs = append(descs, d)
		}
	}
	if len(descs) == 0 {
		return nil, ""
	}
	return descs, yarnSpecName(descs[0])
}

// yarnSpecName extracts the package name from a single `name@descriptor` spec: `@babel/core@^7.0.0` ->
// @babel/core, `lodash@^4` -> lodash, Berry `lodash@npm:^4` -> lodash, aliased `webpack-cli@npm:@scope/x@^4`
// -> webpack-cli. The name ends at the FIRST '@' AFTER index 0 (a leading '@' is the scope), NOT the last
// (the descriptor's protocol target may itself contain '@'). A spec with no such '@' returns "".
func yarnSpecName(spec string) string {
	for i := 1; i < len(spec); i++ {
		if spec[i] == '@' {
			return spec[:i]
		}
	}
	return ""
}

// parseYarnDep parses one dependencies:-block line into a (name, range) pair. It handles both the Yarn v1
// `name "range"` / `"@scope/n" "range"` (space-separated) and the Berry `name: "range"` / `"@scope/n":
// "range"` (colon-separated) forms; the name may be quoted (scoped packages) and the range is unquoted.
func parseYarnDep(line string) (yarnDep, bool) {
	var name, rest string
	if strings.HasPrefix(line, `"`) {
		end := strings.IndexByte(line[1:], '"')
		if end < 0 {
			return yarnDep{}, false
		}
		name, rest = line[1:1+end], line[1+end+1:]
	} else {
		i := strings.IndexAny(line, " :")
		if i < 0 {
			return yarnDep{}, false
		}
		name, rest = line[:i], line[i:]
	}
	rng := strings.Trim(strings.TrimLeft(rest, ": "), `"`)
	name = strings.TrimSpace(name)
	if name == "" || rng == "" {
		return yarnDep{}, false
	}
	return yarnDep{name: name, rng: rng}, true
}

// npmDevDeps reads the companion package.json beside a yarn/pnpm lock (if present) and returns the set of
// direct [devDependencies] names, so the lock's resolved packages can be scoped dev vs prod (yarn.lock
// carries no dev flag). Best-effort – a missing/unreadable manifest yields no dev refinement.
func npmDevDeps(dir string) map[string]bool {
	dev := map[string]bool{}
	if dir == "" {
		return dev
	}
	content, ok := readManifestFile(filepath.Join(dir, "package.json"))
	if !ok {
		return dev
	}
	var pj struct {
		DevDependencies map[string]json.RawMessage `json:"devDependencies"`
	}
	if json.Unmarshal(content, &pj) != nil {
		return dev
	}
	for name := range pj.DevDependencies {
		dev[name] = true
	}
	return dev
}
