package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Cargo is the owned Rust parser: it reads Cargo.lock – the resolved dependency set –
// into cargo components, and reads the COMPANION Cargo.toml (via ParseInput.Dir) to scope direct
// [dev-dependencies] as development, since Cargo.lock itself carries no dev flag. This is the first
// parser to use the widened contract's Dir for a companion read. Components only – the lock's
// `dependencies = [...]` edges are deferred. Hand-parsed (the targeted [[package]] name/version
// + [dev-dependencies] keys), no TOML library, vendor-neutral.
type Cargo struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Cargo) Ecosystem() string { return "cargo" }

// Markers are the lockfile basenames Cargo claims.
func (Cargo) Markers() []string { return []string{"Cargo.lock"} }

// cargoPkg is a Cargo.lock [[package]] block: identity + its dependency entries (each "name" or
// "name version", the version present only to disambiguate when a crate appears at multiple versions).
type cargoPkg struct {
	name, version string
	checksum      string // the [[package]] `checksum` (sha256 hex), when present
	deps          []string
}

// Parse extracts the resolved crates from a Cargo.lock as cargo components + dependency EDGES,
// scoping direct dev-deps from the companion Cargo.toml. Two passes: collect every [[package]] first (a
// `dependencies` entry can reference a crate defined later in the file), then resolve each entry to a
// crate's PURL.
func (Cargo) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil { // honor cancellation before the companion read (Parse does I/O)
		return nil, nil, err
	}
	devNames := cargoDevDeps(in.Dir) // direct [dev-dependencies] from the companion Cargo.toml (best-effort)
	baseScope := sbom.ClassifyScope(in.Path, "")

	// Pass 1: collect the [[package]] blocks (identity + dependency entries).
	var pkgs []cargoPkg
	var cur cargoPkg
	inPkg, inDeps := false, false
	flush := func() {
		if cur.name != "" && cur.version != "" {
			pkgs = append(pkgs, cur)
		}
		cur, inDeps = cargoPkg{}, false
	}
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			flush() // close the previous package block
			inPkg = true
		case strings.HasPrefix(line, "["): // a different table header ends the current package block
			flush()
			inPkg = false
		case inPkg && strings.HasPrefix(line, "name = "):
			cur.name = tomlString(line[len("name = "):])
		case inPkg && strings.HasPrefix(line, "version = "):
			cur.version = tomlString(line[len("version = "):])
		case inPkg && strings.HasPrefix(line, "checksum = "):
			cur.checksum = tomlString(line[len("checksum = "):])
		case inPkg && strings.HasPrefix(line, "dependencies = ["):
			// usually a multi-line array (Cargo's serializer), but may be inline `[…]`/`[]` on this line
			if rest, closed := strings.CutSuffix(strings.TrimPrefix(line, "dependencies = ["), "]"); closed {
				for _, e := range strings.Split(rest, ",") { // inline: parse the entries here; array closes
					if d := strings.Trim(strings.TrimSpace(e), `"`); d != "" {
						cur.deps = append(cur.deps, d)
					}
				}
			} else {
				inDeps = true // multi-line: entries follow on subsequent lines until the closing `]`
			}
		case inDeps && line == "]":
			inDeps = false
		case inDeps: // a quoted dep entry, e.g. `"bar",` or `"baz 2.0.0",`
			if d := strings.Trim(strings.TrimSuffix(line, ","), `"`); d != "" {
				cur.deps = append(cur.deps, d)
			}
		}
	}
	flush() // the final package block
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan Cargo.lock: %w", err)
	}

	// Index crate name -> resolved version(s). Cargo dedups, so a name usually maps to ONE version; when
	// several coexist, a dependency entry carries the explicit version to disambiguate.
	purlOf := func(name, version string) string { return "pkg:cargo/" + name + "@" + version }
	versions := map[string][]string{}
	for _, p := range pkgs {
		versions[p.name] = append(versions[p.name], p.version)
	}
	resolve := func(entry string) (string, bool) {
		f := strings.Fields(entry)
		switch {
		case len(f) >= 2: // "name version [source]" -> the explicit version (verified present)
			for _, v := range versions[f[0]] {
				if v == f[1] {
					return purlOf(f[0], f[1]), true
				}
			}
		case len(f) == 1: // "name" -> the unique version, when unambiguous
			if vs := versions[f[0]]; len(vs) == 1 {
				return purlOf(f[0], vs[0]), true
			}
		}
		return "", false // unresolvable (not in the lock, or ambiguous without a version) -> no edge
	}

	// Pass 2: emit components + resolve edges.
	set := newComponentSet()
	var deps []sbom.Dependency
	for _, p := range pkgs {
		scope := baseScope
		if devNames[p.name] {
			scope = sbom.ScopeDevelopment
		}
		ref := purlOf(p.name, p.version)
		comp := sbom.Component{Name: p.name, Version: p.version, PURL: ref, Location: in.Path, Scope: scope}
		if p.checksum != "" { // Cargo.lock records a sha256 hex per crate
			comp.Checksums = []sbom.Checksum{{Algorithm: "SHA256", Value: p.checksum}}
		}
		set.add(comp)
		seen := map[string]bool{ref: true} // drop duplicate targets + self-edges (parity with the Syft path)
		var on []string
		for _, e := range p.deps {
			if t, ok := resolve(e); ok && !seen[t] {
				seen[t] = true
				on = append(on, t)
			}
		}
		if len(on) > 0 {
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on})
		}
	}
	return set.components(), deps, nil
}

// cargoDevDeps reads the companion Cargo.toml beside Cargo.lock (if present) and returns the set of DIRECT
// [dev-dependencies] names, so the lock's resolved crates can be scoped dev vs prod. Best-effort – no
// manifest, or an unreadable one, yields no dev refinement (everything stays prod/path-scoped). Their
// transitive dev-deps stay prod (Cargo.lock is a flat resolved set; precise dev-transitivity needs the
// graph) – same limitation as the Syft path, which Cargo.lock's lack of a dev flag forces.
func cargoDevDeps(dir string) map[string]bool {
	dev := map[string]bool{}
	if dir == "" {
		return dev
	}
	content, ok := readManifestFile(filepath.Join(dir, "Cargo.toml"))
	if !ok {
		return dev
	}
	inDev := false
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "["):
			// Detect dev-dependency tables by exact dotted SEGMENT (not substring – so [dependencies.
			// my-dev-dependencies] is NOT treated as dev). Two forms:
			// [dev-dependencies] / [target.'cfg(…)'.dev-dependencies] -> harvest the "name =" body lines
			// [dev-dependencies.<crate>] -> the crate name is in the HEADER (next segment); capture it and
			// do NOT harvest the body (version/features are not crate names – harvesting them could
			// mis-scope a real production crate literally named "version").
			inDev = false
			segs := strings.Split(strings.TrimSpace(strings.Trim(line, "[]")), ".")
			for si, seg := range segs {
				if strings.TrimSpace(seg) != "dev-dependencies" {
					continue
				}
				if si == len(segs)-1 {
					inDev = true
				} else if crate := strings.Trim(strings.TrimSpace(segs[si+1]), `"`); crate != "" {
					dev[crate] = true
				}
				break
			}
		case inDev:
			if eq := strings.IndexByte(line, '='); eq > 0 {
				if key := strings.Trim(strings.TrimSpace(line[:eq]), `"`); key != "" {
					dev[key] = true
				}
			}
		}
	}
	return dev
}

// tomlString extracts a double-quoted TOML string value: `"1.2.3"` -> `1.2.3`.
func tomlString(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return s[1 : 1+end]
		}
	}
	return ""
}
