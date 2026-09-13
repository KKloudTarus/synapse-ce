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

// Julia is the owned Julia parser: it reads Manifest.toml – the resolved dependency set produced by Pkg –
// into julia components. Both manifest_format 1.0 (top-level [[Name]] array-of-tables) and 2.0
// ([[deps.Name]]) are handled. A package block carries a `version = "x"`; standard-library packages that
// ship with Julia have no version and are skipped (they are not registry dependencies to match against an
// advisory). Hand-parsed (the targeted array-table header + version line), no TOML library, vendor-neutral.
// It also emits the per-package `deps = ["A","B"]` edges (names only — Manifest.toml records no ranges),
// resolving each dependency name to the versioned package block of the same name. A dependency that resolves
// only to a bundled standard library (no version, no component) contributes no edge.
type Julia struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Julia) Ecosystem() string { return "julia" }

// Markers are the lockfile basenames Julia claims.
func (Julia) Markers() []string { return []string{"Manifest.toml"} }

// Parse extracts the resolved Julia packages from a Manifest.toml. It tracks the current package name from
// each array-table header ([[Name]] or [[deps.Name]]) and reads its `version`; a block with no version
// (a bundled standard library) is skipped. Result is sorted by PURL for deterministic output.
func (Julia) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	scope := sbom.ClassifyScope(in.Path, "")

	// Pass 1: accumulate each package block's name, version, and deps. The version and deps lines can appear
	// in either order within a block, so a block is only flushed at the next table header or EOF.
	type block struct {
		name    string
		version string
		deps    []string
	}
	var blocks []block
	var cur block
	inDepsArray := false // a deps = [ ... ] array that spans multiple lines
	flush := func() {
		if cur.name != "" {
			blocks = append(blocks, cur)
		}
		cur = block{}
		inDepsArray = false
	}
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text())) // drop a trailing # comment so a quoted name in it is not read as a dep
		if inDepsArray {                                         // continue a multi-line deps array until its closing bracket
			cur.deps = append(cur.deps, tomlStringArrayElems(line)...)
			if strings.Contains(line, "]") {
				inDepsArray = false
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]"):
			flush()
			inner := strings.TrimSpace(line[2 : len(line)-2])
			cur.name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(inner, "deps.")), `"`)
		case strings.HasPrefix(line, "["):
			flush() // any other table header ends the package block
		case cur.name != "" && strings.HasPrefix(line, "version") && strings.Contains(line, "="):
			cur.version = tomlString(line[strings.IndexByte(line, '=')+1:])
		case cur.name != "" && strings.HasPrefix(line, "deps") && strings.Contains(line, "="):
			// deps = ["A", "B"] — an inline array of dependency names (a [deps] subtable form is a distinct
			// header handled above and is not read for edges).
			rhs := line[strings.IndexByte(line, '=')+1:]
			cur.deps = append(cur.deps, tomlStringArrayElems(rhs)...)
			if strings.Contains(rhs, "[") && !strings.Contains(rhs, "]") {
				inDepsArray = true
			}
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("parse Manifest.toml: %w", err)
	}

	// Pass 2: index versioned packages by name, emit components + resolve deps to edges.
	index := map[string]string{}
	for _, b := range blocks {
		if b.version != "" {
			index[b.name] = "pkg:julia/" + b.name + "@" + b.version
		}
	}
	set := newComponentSet()
	var deps []sbom.Dependency
	for _, b := range blocks {
		if b.version == "" {
			continue // a bundled standard library: not a registry component
		}
		ref := index[b.name]
		set.add(sbom.Component{Name: b.name, Version: b.version, PURL: ref, Location: in.Path, Scope: scope})
		seen := map[string]bool{ref: true}
		var on []string
		for _, d := range b.deps {
			t, ok := index[strings.TrimSpace(d)]
			if !ok || seen[t] {
				continue
			}
			seen[t] = true
			on = append(on, t)
		}
		if len(on) > 0 {
			sort.Strings(on)
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on, Scope: scope})
		}
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return comps, deps, nil
}

// tomlStringArrayElems extracts the double-quoted string elements from a fragment of a TOML inline array
// (e.g. `["Foo", "Bar"]` or a continuation line `"Bar",`). It is deliberately minimal: it collects quoted
// tokens and ignores brackets/commas, so it composes across the lines of a multi-line array.
func tomlStringArrayElems(s string) []string {
	var out []string
	for {
		i := strings.IndexByte(s, '"')
		if i < 0 {
			return out
		}
		s = s[i+1:]
		j := strings.IndexByte(s, '"')
		if j < 0 {
			return out
		}
		if e := strings.TrimSpace(s[:j]); e != "" {
			out = append(out, e)
		}
		s = s[j+1:]
	}
}
