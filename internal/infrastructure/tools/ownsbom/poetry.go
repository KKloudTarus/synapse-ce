package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
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

type poetryDep struct {
	name       string
	optional   bool
	constraint string // the declared version constraint (D3.8): `"^1.2"` or a table's version=…
}

// poetryPkg is a [[package]] block collected in pass 1: identity + the direct dependency names from its
// [package.dependencies] sub-table (resolved to edges in pass 2).
type poetryPkg struct {
	name, version, category string
	hash                    string      // first artifact hash ("sha256:<hex>") from the package's own `files = [...]` (lock v2.0)
	deps                    []poetryDep // direct dependencies + explicit optional=true metadata
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
			// A dep entry is `name = "constraint"` or `name = {version=…, optional=true}`. The key names the
			// package; optionality is captured only when the same TOML value explicitly says optional=true.
			// Multi-line continuation elements are filtered by isPoetryDepKey and never guessed as optional.
			i := strings.IndexByte(line, '=')
			if k := strings.Trim(strings.TrimSpace(line[:i]), `"`); isPoetryDepKey(k) {
				raw := strings.TrimSpace(line[i+1:])
				value := strings.ToLower(strings.ReplaceAll(raw, " ", ""))
				cur.deps = append(cur.deps, poetryDep{name: k, optional: strings.Contains(value, "optional=true"), constraint: poetryDepConstraint(raw)})
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

	// Pass 2: emit components + resolve edges, splitting required and optional relationships.
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
		// Per resolved target, the WINNING declaration decides both the edge's optionality and its recorded
		// range. Priority: a required declaration (2) beats an optional one (1), and a strict > keeps the FIRST
		// declaration at a given priority (a later required tie does not overwrite an earlier one). The range is
		// then the winner's OWN constraint – empty when that winner declared none (a git/path/url dependency),
		// so a losing declaration's range can never leak onto the edge.
		targetOptional := map[string]bool{}
		targetRange := map[string]string{}
		winnerPrio := map[string]int{}
		for _, d := range p.deps {
			dn := normalizePyPI(d.name)
			vs := versionsOf[dn]
			if len(vs) != 1 {
				continue // no [[package]] entry (e.g. the python constraint) OR an ambiguous duplicate name – no edge
			}
			t := purlOf(dn, vs[0])
			if t == ref {
				continue
			}
			prio := 1 // optional
			if !d.optional {
				prio = 2 // required wins over an alternate optional declaration
			}
			if prio > winnerPrio[t] { // strict > keeps the first declaration at a given priority
				winnerPrio[t] = prio
				targetOptional[t] = d.optional
				targetRange[t] = d.constraint // the winner's own constraint (may be empty -> range absent)
			}
		}
		var required, optional []string
		for target, isOptional := range targetOptional {
			if isOptional {
				optional = append(optional, target)
			} else {
				required = append(required, target)
			}
		}
		sort.Strings(required)
		sort.Strings(optional)
		if len(required) > 0 {
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: required, Scope: scope, RequestedRanges: rangesFor(required, targetRange)})
		}
		if len(optional) > 0 {
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: optional, Scope: scope, Optional: true, RequestedRanges: rangesFor(optional, targetRange)})
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

// poetryTableVersionRE matches the `version` KEY inside an inline dependency table body and captures its
// double-quoted value whole. The key must be at the body start or preceded by a comma or whitespace, so a
// `python-versions` (or any other marker) key that merely CONTAINS the substring "version" never matches.
// Capturing the quoted value as one group keeps a comma inside the constraint (`">=1,<2"`) intact, which a
// naive comma-split would sever. It is applied only to the table body (see poetryInlineTableBody), never the
// raw RHS, so a `version = "…"` in a trailing `# comment` after the closing brace can never be read as a key.
var poetryTableVersionRE = regexp.MustCompile(`(?:^|[{,\s])version\s*=\s*"([^"]*)"`)

// poetryInlineTableBody returns the body of a `{…}` inline table – the text between the opening brace and its
// MATCHING closing brace – skipping any `}` that appears inside a double-quoted string value (honoring `\"`
// escapes). Anything after the closing brace (a trailing `# comment`, another table) is excluded. It returns
// "" for a non-table or an unterminated table, so a malformed line yields no range rather than a guessed one.
func poetryInlineTableBody(raw string) string {
	if len(raw) == 0 || raw[0] != '{' {
		return ""
	}
	inStr, esc := false, false
	for i := 1; i < len(raw); i++ {
		switch c := raw[i]; {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case c == '}' && !inStr:
			return raw[1:i]
		}
	}
	return "" // unterminated inline table – no reliable body, so no range
}

// poetryDepConstraint extracts the declared version constraint from a poetry.lock dependency value:
// a bare TOML string ("^1.2") or an inline table's version field ({version = "^1.2", optional = true}).
// A table with no version key (a git/path/url dependency) yields "" (D3.8).
func poetryDepConstraint(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if raw[0] == '"' {
		return tomlString(raw)
	}
	if raw[0] == '{' {
		if m := poetryTableVersionRE.FindStringSubmatch(poetryInlineTableBody(raw)); m != nil {
			return m[1]
		}
	}
	return ""
}
