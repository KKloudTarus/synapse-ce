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
//	{:dep_name, "~> 1.0", [hex: :real_package, ...]}
//
// capturing the dependency's atom name (group 1), its declared version requirement (group 2), and the
// OPTIONAL `hex: :real_package` rename (group 3): a dep whose atom differs from its published Hex package
// carries the real package name here, and that name is what the lock keys the component by. The outer
// `{:hex, :pkg, "ver"}` tuple never matches (`:pkg` is an atom, not a quoted string, so there is no
// `:name, "…"` shape after it); `[^}]` keeps the optional rename inside the current tuple.
var hexDepTuple = regexp.MustCompile(`\{\s*:([a-zA-Z0-9_]+)\s*,\s*"([^"]*)"(?:[^}]*?\bhex:\s*:([a-zA-Z0-9_]+))?`)

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
	type hexReq struct{ name, rng string }
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
			name := dm[1]
			if dm[3] != "" { // a `hex: :real_package` rename: the lock keys the component by the real name
				name = dm[3]
			}
			p.reqs = append(p.reqs, hexReq{name: name, rng: dm[2]})
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
		var on []string
		for _, r := range p.reqs {
			t, ok := index[r.name]
			if !ok || seen[t] {
				continue
			}
			seen[t] = true
			on = append(on, t)
			if r.rng != "" {
				byTarget[t] = r.rng
			}
		}
		if len(on) > 0 {
			sort.Strings(on)
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on, Scope: baseScope, RequestedRanges: rangesFor(on, byTarget)})
		}
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL }) // deterministic order (mirror swift/dart)
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return comps, deps, nil
}
