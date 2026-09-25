package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Bun is the owned Bun parser: npm-ecosystem packages resolved by Bun's own installer. It reads the
// FULL resolved set from bun.lock's top-level "packages" map.
//
// bun.lock is JSON with two relaxations Bun's writer emits and encoding/json rejects: trailing commas
// before a closing brace or bracket, and // line comments. Rather than take a JSONC dependency (the
// owned parsers stay vendor-neutral and dependency-light, as pnpm.go says of YAML), the relaxations are
// removed by a string-aware pass before the standard decoder runs.
//
// Each packages entry is an array whose FIRST element is the resolved "name@version" spec, and whose
// THIRD element, when present, is an object carrying that package's own dependency maps. Components come
// from the first element; dependency EDGES come from the third, resolved against the emitted-component
// index exactly as npm.go and pnpm.go do (resolution-as-filter: an edge is kept only when both endpoints
// are emitted components). There is no synthetic project-root node, so a direct dependency is one nothing
// else depends on, matching the other npm-family parsers.
//
// A workspace entry, a "catalog:" reference and a "workspace:*" reference carry no resolved version and
// are deliberately not components: emitting them would put an unversioned row in the inventory that no
// advisory can match, which reads as coverage the scan does not have.
type Bun struct{}

// Ecosystem identifies this parser's package ecosystem (Bun resolves npm packages).
func (Bun) Ecosystem() string { return "npm" }

// Markers are the lockfile basenames Bun claims. bun.lockb, the older binary format, is deliberately not
// claimed: it cannot be read without Bun itself, and silently claiming it would report an empty inventory
// for a repository that has dependencies.
func (Bun) Markers() []string { return []string{"bun.lock"} }

const maxBunLockBytes = 32 << 20

// bunPackageEntry is one packages-map value. Bun writes a heterogeneous array, so it is decoded as raw
// messages and each position is read for what it is known to hold.
type bunPackageEntry []json.RawMessage

// bunDependencyMaps is the third array element: the package's own dependency maps.
type bunDependencyMaps struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type bunLock struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]bunPackageEntry `json:"packages"`
}

// Parse extracts the resolved Bun packages and their edges from a bun.lock.
func (Bun) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if len(in.Content) > maxBunLockBytes {
		return nil, nil, fmt.Errorf("%w: bun.lock exceeds %d bytes", shared.ErrValidation, maxBunLockBytes)
	}
	var lock bunLock
	if err := json.Unmarshal(relaxJSON(in.Content), &lock); err != nil {
		return nil, nil, fmt.Errorf("parse bun.lock: %w", err)
	}
	baseScope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	purlByName := map[string]string{} // package name → PURL: the emitted-component index for edge resolution
	type rawEdge struct {
		parent string
		child  string
	}
	var edges []rawEdge

	names := make([]string, 0, len(lock.Packages))
	for name := range lock.Packages {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic output regardless of map order

	for _, key := range names {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		entry := lock.Packages[key]
		if len(entry) == 0 {
			continue
		}
		var spec string
		if err := json.Unmarshal(entry[0], &spec); err != nil {
			continue // a shape we do not model contributes nothing rather than a wrong component
		}
		name, version, ok := bunSpecNameVersion(spec)
		if !ok {
			continue
		}
		purlName := name
		if strings.HasPrefix(purlName, "@") {
			purlName = "%40" + purlName[1:] // PURL spec: scoped @ → %40 (matches the npm/yarn/pnpm parsers)
		}
		purl := "pkg:npm/" + purlName + "@" + version
		set.add(sbom.Component{Name: name, Version: version, PURL: purl, Location: in.Path, Scope: baseScope})
		purlByName[name] = purl

		if len(entry) < 3 {
			continue
		}
		var deps bunDependencyMaps
		if err := json.Unmarshal(entry[2], &deps); err != nil {
			continue // the dependency object is optional; a shape we cannot read costs edges, never components
		}
		for _, m := range []map[string]string{deps.Dependencies, deps.OptionalDependencies, deps.PeerDependencies} {
			for child := range m {
				edges = append(edges, rawEdge{parent: name, child: child})
			}
		}
	}

	comps := set.components()
	seen := map[string]bool{}
	var out []sbom.Dependency
	for _, e := range edges {
		from, okFrom := purlByName[e.parent]
		to, okTo := purlByName[e.child]
		if !okFrom || !okTo || from == to {
			continue // resolution-as-filter: an edge to something not emitted is not an edge
		}
		key := from + "\x00" + to
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, sbom.Dependency{Ref: from, DependsOn: []string{to}})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ref != out[j].Ref {
			return out[i].Ref < out[j].Ref
		}
		return out[i].DependsOn[0] < out[j].DependsOn[0]
	})
	return comps, out, nil
}

// bunSpecNameVersion splits a resolved "name@version" spec. The name may be scoped and therefore start
// with its own @, so the LAST @ separates the two. A spec with no version, which is what a workspace or
// catalog reference looks like, is rejected rather than emitted unversioned.
func bunSpecNameVersion(spec string) (name, version string, ok bool) {
	spec = strings.TrimSpace(spec)
	at := strings.LastIndex(spec, "@")
	if at <= 0 || at == len(spec)-1 {
		return "", "", false
	}
	name, version = spec[:at], spec[at+1:]
	if name == "" || version == "" {
		return "", "", false
	}
	// A workspace or catalog protocol is a reference, not a resolved version.
	if strings.Contains(version, ":") {
		return "", "", false
	}
	return name, version, true
}

// relaxJSON removes the two things Bun's writer emits that encoding/json rejects: a trailing comma before
// a closing brace or bracket, and a // line comment. It is string-aware, so a comma or a // inside a
// quoted value (a URL, a base64 integrity hash) is preserved. Byte length is not preserved and does not
// need to be: nothing downstream indexes into the original.
func relaxJSON(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out = append(out, '\n')
			}
		case c == ',':
			// Look ahead past whitespace: a comma followed by a closer is trailing.
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue // drop it
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
