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
	set := newComponentSet()
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		m := hexEntry.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		name, version := m[1], m[2]
		set.add(sbom.Component{
			Name:     name,
			Version:  version,
			PURL:     "pkg:hex/" + name + "@" + version,
			Location: in.Path,
			Scope:    baseScope,
		})
	}
	if err := sc.Err(); err != nil {
		// Fail loud on a truncated / over-long-line lockfile (no silent undercount) – matches the package's
		// fail-loud doctrine + the other line-scan parsers (dart/gem/cargo/…).
		return nil, nil, fmt.Errorf("scan mix.lock: %w", err)
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL }) // deterministic order (mirror swift/dart)
	return comps, nil, nil
}
