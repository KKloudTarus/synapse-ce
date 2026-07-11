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
// Components only – the per-package `deps` edges are deferred.
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
	set := newComponentSet()

	curName := ""
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]"):
			// An array-table header opens a new package block: [[Name]] (format 1.0) or
			// [[deps.Name]] (format 2.0). A subsequent version line binds to this name.
			inner := strings.TrimSpace(line[2 : len(line)-2])
			curName = strings.TrimPrefix(inner, "deps.")
			curName = strings.Trim(strings.TrimSpace(curName), `"`)
		case strings.HasPrefix(line, "["):
			curName = "" // any other table header ends the package block
		case curName != "" && strings.HasPrefix(line, "version") && strings.Contains(line, "="):
			version := tomlString(line[strings.IndexByte(line, '=')+1:])
			if version == "" {
				continue
			}
			set.add(sbom.Component{
				Name:     curName,
				Version:  version,
				PURL:     "pkg:julia/" + curName + "@" + version,
				Location: in.Path,
				Scope:    scope,
			})
			curName = "" // one version per package block; avoid a stray later match rebinding it
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("parse Manifest.toml: %w", err)
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, nil, nil
}
