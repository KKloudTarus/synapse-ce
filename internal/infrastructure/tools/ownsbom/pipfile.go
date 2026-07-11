package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Pipfile is the owned Python-via-Pipenv parser: it reads Pipfile.lock – the resolved
// dependency set – into pypi components (pkg:pypi/<name>@<version>). Pipfile.lock is JSON with two objects:
// "default" (production) and "develop" (development), each {name: {version: "==x.y.z", …}}. The dev split is
// INLINE in the lock (no companion needed). Pipenv pins exactly, so versions carry an "==" operator we strip;
// an entry with no concrete version (a VCS/editable ref) is skipped (no resolvable version → no match). Names
// are PEP 503-normalized (shared with the requirements/poetry parsers). Components only – edges are not
// emitted yet. Vendor-neutral (stdlib encoding/json), no third-party Pipenv library.
type Pipfile struct{}

// Ecosystem identifies this parser's package ecosystem (Pipenv resolves PyPI packages).
func (Pipfile) Ecosystem() string { return "pypi" }

// Markers are the lockfile basenames Pipfile claims.
func (Pipfile) Markers() []string { return []string{"Pipfile.lock"} }

// pipfileLock is the subset of Pipfile.lock we parse: the two resolved-package objects.
type pipfileLock struct {
	Default map[string]pipfilePkg `json:"default"`
	Develop map[string]pipfilePkg `json:"develop"`
}

type pipfilePkg struct {
	Version string   `json:"version"`
	Hashes  []string `json:"hashes"` // "sha256:<hex>" per acceptable artifact file
}

// pyHashChecksums converts a Python lockfile hash list ("<alg>:<hex>", e.g. "sha256:abc…", as Pipfile.lock
// and poetry.lock record one per artifact file) into component Checksums, keeping the FIRST hash of each
// algorithm (the files share an algorithm but differ per wheel/sdist, and one representative digest is enough
// for integrity). Malformed entries are skipped; returns nil when none parse.
func pyHashChecksums(hashes []string) []sbom.Checksum {
	seen := map[string]bool{}
	var out []sbom.Checksum
	for _, h := range hashes {
		i := strings.IndexByte(h, ':')
		if i <= 0 || i == len(h)-1 {
			continue // not "<alg>:<value>"
		}
		alg := strings.ToUpper(strings.TrimSpace(h[:i]))
		val := strings.TrimSpace(h[i+1:])
		if alg == "" || val == "" || seen[alg] {
			continue
		}
		seen[alg] = true
		out = append(out, sbom.Checksum{Algorithm: alg, Value: val})
	}
	return out
}

// Parse extracts the resolved Python packages: "default" as production, "develop" as development. Each
// version is a Pipenv exact pin like "==2.31.0" → the bare version. Production is added first so a package
// in both objects keeps the safer production scope (componentSet dedups by PURL).
func (Pipfile) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var lock pipfileLock
	if err := json.Unmarshal(in.Content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}
	baseScope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	add := func(pkgs map[string]pipfilePkg, scope string) {
		for rawName, p := range pkgs {
			name := normalizePyPI(strings.TrimSpace(rawName))
			// Pipenv pins exactly: "==2.31.0". Strip the operator; a non-"==" / empty version (VCS/editable
			// ref, or a "*" left unresolved) is not a concrete pin → skip (componentSet drops empty anyway).
			version := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(p.Version), "=="))
			if name == "" || !sbom.IsResolvedVersion(version) {
				continue
			}
			set.add(sbom.Component{
				Name:      name,
				Version:   version,
				PURL:      "pkg:pypi/" + name + "@" + version,
				Location:  in.Path,
				Scope:     scope,
				Checksums: pyHashChecksums(p.Hashes),
			})
		}
	}
	add(lock.Default, baseScope)
	add(lock.Develop, sbom.ScopeDevelopment)
	// Pipfile.lock's default/develop are JSON MAPS (unordered), so sort the output by PURL for a
	// deterministic component list (mirrors the NuGet/Dart/Elixir/Swift map-source parsers).
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, nil, nil
}
