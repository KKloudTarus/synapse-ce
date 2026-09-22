package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// hexEntry matches a mix.lock Hex dependency line:
//
//	"name": {:hex,:pkg, "1.2.3", "hash", [:mix], [deps...], "hexpm", "hash"},
//
// capturing the package name + the resolved version. A non-Hex dep (`:git` / `:path`) does not match – it
// carries no Hex package version to catalog – and is skipped.
var hexEntry = regexp.MustCompile(`^\s*"([^"]+)":\s*\{\s*:hex\s*,\s*:[a-zA-Z0-9_]+\s*,\s*"([^"]+)"`)

// hexDepTuple matches a nested dependency tuple inside a mix.lock entry's deps list:
//
//	{:dep_name, "~> 1.0", [hex: :real_package, optional: true]}
//
// capturing the dependency's atom name (group 1), its declared version requirement (group 2), and the
// tuple's option tail up to its closing brace (group 3), from which the OPTIONAL `hex: :real_package`
// rename and the `optional: true` flag are read (see hexRename / hexOptionalTrue). The outer
// `{:hex, :pkg, "ver"}` tuple never matches (`:pkg` is an atom, not a quoted string, so there is no
// `:name, "…"` shape after it); `[^}]` keeps the captured tail inside the current tuple.
var hexDepTuple = regexp.MustCompile(`\{\s*:([a-zA-Z0-9_]+)\s*,\s*"([^"]*)"([^}]*)`)

// hexRename extracts a `hex: :real_package` rename from a dep tuple's option tail; hexOptionalTrue detects
// the `optional: true` flag. A dep with `optional: false` or no flag is a required edge; `optional: true`
// records a parent-declared optional edge (emitted as a separate Dependency with Optional set).
var (
	hexRename       = regexp.MustCompile(`\bhex:\s*:([a-zA-Z0-9_]+)`)
	hexOptionalTrue = regexp.MustCompile(`\boptional:\s*true\b`)
)

// Elixir is the owned Elixir/Erlang parser: it reads a mix.lock – the resolved dependency
// set of a Mix project – into Hex components (pkg:hex/<name>@<version>, OSV ecosystem "Hex"). mix.lock is an
// Elixir map literal; each Hex entry is `"name": {:hex,:pkg, "version", …}`. Only Hex deps are cataloged (a
// :git/:path dep has no Hex package version). Vendor-neutral: a bounded line-scan, no third-party Elixir
// library. mix.lock is flat (no inline prod/dev split), so all deps take the path's base scope.
type Elixir struct{}

// Ecosystem identifies this parser's package ecosystem (the Hex PURL type).
func (Elixir) Ecosystem() string { return "hex" }

// Markers are the lockfile basenames Elixir claims.
func (Elixir) Markers() []string { return []string{"mix.lock"} }

// Parse extracts the resolved Hex packages from a mix.lock as hex components.
func (Elixir) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	baseScope := sbom.ClassifyScope(in.Path, "")
	// Pass 1: collect each Hex entry with its name, version, and the deps tuples on its line. Two passes are
	// needed because a dep can name a package defined later in the (unordered) lockfile.
	type hexReq struct {
		name, rng string
		optional  bool
	}
	type hexPkg struct {
		name, version string
		reqs          []hexReq
	}
	var pkgs []hexPkg
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := stripInlineComment(sc.Text()) // a `# {:dep, "req"}` comment must not be read as a real dep tuple
		m := hexEntry.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		p := hexPkg{name: m[1], version: m[2]}
		for _, dm := range hexDepTuple.FindAllStringSubmatch(line, -1) {
			name, opts := dm[1], dm[3]
			if rn := hexRename.FindStringSubmatch(opts); rn != nil { // `hex: :real_package`: the lock keys the component by the real name
				name = rn[1]
			}
			p.reqs = append(p.reqs, hexReq{name: name, rng: dm[2], optional: hexOptionalTrue.MatchString(opts)})
		}
		pkgs = append(pkgs, p)
	}
	if err := sc.Err(); err != nil {
		// Fail loud on a truncated / over-long-line lockfile (no silent undercount) – matches the package's
		// fail-loud doctrine + the other line-scan parsers (dart/gem/cargo/…).
		return nil, nil, fmt.Errorf("scan mix.lock: %w", err)
	}

	// Pass 2: index by name, emit components + edges. A dep atom that renames its Hex package via [hex: :real]
	// is resolved by name here; an unresolved dep (a :git/:path dep or a renamed one absent from the lock) is
	// skipped rather than fabricated.
	index := map[string]string{}
	for _, p := range pkgs {
		index[p.name] = "pkg:hex/" + p.name + "@" + p.version
	}
	set := newComponentSet()
	var deps []sbom.Dependency
	for _, p := range pkgs {
		ref := index[p.name]
		set.add(sbom.Component{Name: p.name, Version: p.version, PURL: ref, Location: in.Path, Scope: baseScope})
		seen := map[string]bool{ref: true}
		byTarget := map[string]string{}
		targetOptional := map[string]bool{}
		for _, r := range p.reqs {
			t, ok := index[r.name]
			if !ok || seen[t] {
				continue
			}
			seen[t] = true
			targetOptional[t] = r.optional
			if r.rng != "" {
				byTarget[t] = r.rng
			}
		}
		// Split required from parent-declared-optional edges into separate Dependency records, mirroring the
		// poetry/yarn/npm parsers, so a consumer can tell an optional edge from a required one.
		var required, optional []string
		for t, isOptional := range targetOptional {
			if isOptional {
				optional = append(optional, t)
			} else {
				required = append(required, t)
			}
		}
		sort.Strings(required)
		sort.Strings(optional)
		if len(required) > 0 {
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: required, Scope: baseScope, RequestedRanges: rangesFor(required, byTarget)})
		}
		if len(optional) > 0 {
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: optional, Scope: baseScope, Optional: true, RequestedRanges: rangesFor(optional, byTarget)})
		}
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL }) // deterministic order (mirror swift/dart)
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return comps, deps, nil
}
