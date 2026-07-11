package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Poetry is the owned Python-via-Poetry parser (components + edges): it reads poetry.lock – the
// resolved dependency set as TOML [[package]] blocks – into pypi components (pkg:pypi/<name>@<version>) AND
// the dependency edges between them. Resolved versions come from the lock; the dev/prod scope comes from the
// block's `category = "dev"` (Poetry <1.5, inline) when present, else the file path. Names are PEP 503-
// normalized (shared with the requirements parser). Each package's `[package.dependencies]` sub-table names
// its direct deps; each dep is resolved to the matching [[package]]'s PURL – a dep with no [[package]] entry
// (e.g. the `python` constraint, or an extras-only marker) yields no edge, so an odd/unparsed entry is
// silently dropped rather than mis-linked. Reuses the [[package]] scan (shared with Cargo) – hand-parsed, no
// TOML library, vendor-neutral.
type Poetry struct{}

// Ecosystem identifies this parser's package ecosystem (Poetry resolves PyPI packages).
func (Poetry) Ecosystem() string { return "pypi" }

// Markers are the lockfile basenames Poetry claims.
func (Poetry) Markers() []string { return []string{"poetry.lock"} }

// poetryPkg is a [[package]] block collected in pass 1: identity + the direct dependency names from its
// [package.dependencies] sub-table (resolved to edges in pass 2).
type poetryPkg struct {
	name, version, category string
	hash                    string   // first artifact hash ("sha256:<hex>") from the package's own `files = [...]` (lock v2.0)
	deps                    []string // raw direct-dependency names from [package.dependencies]
}

// Parse extracts the resolved packages + their dependency edges from a poetry.lock. The artifact-hash
// capture assumes the canonical poetry/tomlkit layout where a files/`[metadata.files]` array's closing `]`
// is on its own line (it always is); a compact closer just means the hash is not captured, never a mis-attribution.
func (Poetry) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil { // honor cancellation before parsing (parity with the sibling parsers)
		return nil, nil, err
	}
	baseScope := sbom.ClassifyScope(in.Path, "")

	// Pass 1: collect the [[package]] blocks (identity + the direct dep names from [package.dependencies];
	// a dep can reference a package defined later in the file, so edges are resolved in pass 2).
	var pkgs []poetryPkg
	var cur poetryPkg
	inPkg, inDeps, inFiles := false, false, false
	// Lock v1 (< 2.0) stores hashes in a trailing [metadata.files] table keyed by package name, not per
	// package; collect them here and attach in pass 2 to whichever layout the lock used.
	inMeta := false
	metaName := ""
	metaHashes := map[string]string{}
	flush := func() {
		if cur.name != "" && cur.version != "" {
			pkgs = append(pkgs, cur)
		}
		cur, inDeps, inFiles = poetryPkg{}, false, false
	}
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// Lock v2.0: the current package's own `files = [ {file=…, hash="sha256:…"} ]` array.
		if inFiles {
			if strings.HasPrefix(line, "[") {
				// An unterminated files array (missing `]`): a new table/[[package]] ends it. Exit and fall
				// through so the boundary line is handled below – never swallow later packages (no silent gap).
				inFiles = false
			} else {
				if line == "]" {
					inFiles = false
				} else if cur.hash == "" {
					cur.hash = poetryFileHash(line) // keep the first artifact hash; "" if the line has none
				}
				continue
			}
		}
		// Lock v1: the trailing [metadata.files] table – `name = [ {file=…, hash="sha256:…"} ]`.
		if inMeta && !strings.HasPrefix(line, "[") {
			switch {
			case metaName == "":
				if i := strings.IndexByte(line, '='); i > 0 && strings.Contains(line[i:], "[") {
					metaName = normalizePyPI(strings.Trim(strings.TrimSpace(line[:i]), `"`))
				}
			case line == "]":
				metaName = ""
			default:
				if h := poetryFileHash(line); h != "" {
					if _, ok := metaHashes[metaName]; !ok {
						metaHashes[metaName] = h
					}
				}
			}
			continue
		}
		switch {
		case line == "[[package]]":
			flush() // close the previous package block
			inPkg, inMeta = true, false
		case line == "[metadata.files]":
			flush()
			inPkg, inMeta, metaName = false, true, ""
		case line == "[package.dependencies]":
			inDeps = true // the current package's direct deps follow – stay associated with cur (do NOT flush)
		case strings.HasPrefix(line, "["): // any other table ([package.extras]/[package.source]/[metadata]/…) ends the block
			flush()
			inPkg, inMeta = false, false
		case inPkg && line == "files = [": // lock v2.0 per-package artifact hashes
			inFiles = true
		case inDeps && strings.ContainsRune(line, '='):
			// a dep entry `name = "constraint"` or `name = {version=…}`: the KEY (before the first =) is the
			// dep name. A non-package-name key (e.g. a "{" array element) is filtered; an unresolvable name
			// produces no edge in pass 2, so a stray entry is harmless.
			if k := strings.Trim(strings.TrimSpace(line[:strings.IndexByte(line, '=')]), `"`); isPoetryDepKey(k) {
				cur.deps = append(cur.deps, k)
			}
		case inPkg && strings.HasPrefix(line, "name = "):
			cur.name = tomlString(line[len("name = "):])
		case inPkg && strings.HasPrefix(line, "version = "):
			cur.version = tomlString(line[len("version = "):])
		case inPkg && strings.HasPrefix(line, "category = "):
			cur.category = tomlString(line[len("category = "):])
		}
	}
	flush() // the final package block
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan poetry.lock: %w", err)
	}

	// Index normalized name -> resolved version(s). A real poetry.lock is deduped (one version per name); a
	// name mapping to MORE than one version (a malformed/crafted lock) is ambiguous and resolves to NO edge,
	// mirroring Cargo's resolver – never guess which same-named package an edge points at.
	purlOf := func(name, version string) string { return "pkg:pypi/" + name + "@" + version }
	versionsOf := map[string][]string{}
	for _, p := range pkgs {
		n := normalizePyPI(p.name)
		versionsOf[n] = append(versionsOf[n], p.version)
	}

	// Pass 2: emit components + resolve edges.
	set := newComponentSet()
	var deps []sbom.Dependency
	for _, p := range pkgs {
		n := normalizePyPI(p.name)
		scope := baseScope
		if strings.EqualFold(p.category, "dev") {
			scope = sbom.ScopeDevelopment
		}
		ref := purlOf(n, p.version)
		hash := p.hash // lock v2.0 per-package files; fall back to the v1 [metadata.files] table
		if hash == "" {
			hash = metaHashes[n]
		}
		set.add(sbom.Component{Name: n, Version: p.version, PURL: ref, Location: in.Path, Scope: scope, Checksums: pyHashChecksums([]string{hash})})
		seen := map[string]bool{ref: true} // drop self-edges + duplicate targets
		var on []string
		for _, d := range p.deps {
			dn := normalizePyPI(d)
			vs := versionsOf[dn]
			if len(vs) != 1 {
				continue // no [[package]] entry (e.g. the python constraint) OR an ambiguous duplicate name – no edge
			}
			if t := purlOf(dn, vs[0]); !seen[t] {
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

// poetryFileHash extracts the `hash = "sha256:<hex>"` value from a poetry.lock files-array entry line
// (`{file = "…", hash = "sha256:…"}`), returning the full "alg:hex" token or "" when the line carries none.
func poetryFileHash(line string) string {
	i := strings.Index(line, "hash = ")
	if i < 0 {
		return ""
	}
	return tomlString(line[i+len("hash = "):])
}

// isPoetryDepKey reports whether a [package.dependencies] line's key is a package-name token (starts
// alphanumeric) – filtering multi-line-value continuation lines (e.g. an array element starting with "{").
func isPoetryDepKey(k string) bool {
	if k == "" {
		return false
	}
	c := k[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
