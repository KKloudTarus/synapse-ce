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

// UV is the owned Python-via-uv parser. It reads registry-backed packages from uv.lock [[package]] blocks and
// emits normalized PyPI components plus the resolved dependency graph.
//
// Only packages with a non-empty name, concrete resolved version, and canonical registry source are emitted.
// Local, editable, virtual, Git, and direct-URL package sources are skipped. Each package's resolved
// `dependencies = [{ name = "..." }, ...]` array becomes package-to-package edges, resolved against the
// emitted components (resolution-as-filter): an edge to a name that is not an emitted component, or to a name
// that resolves ambiguously to more than one version (a universal lock listing several versions of the same
// name), is dropped so a wrong edge is never invented. optional/dev dependency groups are deferred (they are
// separate sub-tables and carry conditional/dev scope), keeping the emitted graph the production runtime one.
//
// The parser targets uv's canonical generated TOML layout, uses only the Go standard library, and performs no
// network or external-command execution.
type UV struct{}

// Ecosystem returns the package ecosystem for uv components.
func (UV) Ecosystem() string {
	return "pypi"
}

// Markers returns the expected lockfile basename.
func (UV) Markers() []string {
	return []string{"uv.lock"}
}

type uvPackage struct {
	name     string
	version  string
	registry bool
	deps     []string
}

func uvTOMLAssignment(line string) (key string, value string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}

	key = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])

	if key == "" || value == "" {
		return "", "", false
	}

	return key, value, true
}

func uvRegistrySource(value string) bool {
	value = strings.TrimSpace(value)

	if len(value) < 2 || value[0] != '{' || value[len(value)-1] != '}' {
		return false
	}

	inner := strings.TrimSpace(value[1 : len(value)-1])

	key, rawValue, ok := uvTOMLAssignment(inner)
	if !ok || key != "registry" {
		return false
	}

	rawValue = strings.TrimSpace(rawValue)
	registry := strings.TrimSpace(tomlString(rawValue))
	if registry == "" {
		return false
	}

	// Accept only the canonical single-field form:
	// source = { registry = "..." }
	return rawValue == `"`+registry+`"`
}

// uvDependencyNames extracts the dependency package names from a uv.lock `dependencies` inline-table array
// (`[{ name = "a" }, { name = "b", marker = "..." }]`), which may span several lines. Each entry's name is
// uv's always-first field, read as the first quoted string of the object, so an `extra = [...]` or `marker`
// field on the same entry is ignored. `{`/`}` depth delimits entries; the array's own `[]` are not counted
// here (the caller handles multi-line accumulation).
func uvDependencyNames(arrayText string) []string {
	var names []string
	depth := 0
	start := -1
	for i := 0; i < len(arrayText); i++ {
		switch arrayText[i] {
		case '{':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					if n := uvFirstName(arrayText[start:i]); n != "" {
						names = append(names, n)
					}
					start = -1
				}
			}
		}
	}
	return names
}

// uvFirstName reads the `name = "..."` value from a dependency inline-table object's content. uv always
// serializes name as the object's first field, so this requires the object to start with the `name` key and
// returns the first double-quoted string after its `=`; anything else yields "" (no guessed name).
func uvFirstName(obj string) string {
	s := strings.TrimSpace(obj)
	if !strings.HasPrefix(s, "name") {
		return ""
	}
	s = strings.TrimSpace(s[len("name"):])
	if !strings.HasPrefix(s, "=") {
		return ""
	}
	s = s[1:]
	a := strings.IndexByte(s, '"')
	if a < 0 {
		return ""
	}
	rest := s[a+1:]
	b := strings.IndexByte(rest, '"')
	if b < 0 {
		return ""
	}
	return rest[:b]
}

// Parse extracts resolved registry packages from a uv.lock file as deterministic PyPI components and the
// resolved dependency edges between them.
func (UV) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	scope := sbom.ClassifyScope(in.Path, "")

	// Pass 1: collect every [[package]] block (name, version, source, resolved dependency names).
	var pkgs []uvPackage
	var cur uvPackage
	inPackage := false

	var depsText strings.Builder
	collectingDeps := false
	bracket := 0

	flush := func() {
		if inPackage {
			pkgs = append(pkgs, cur)
		}
		cur = uvPackage{}
	}

	finishDeps := func() {
		cur.deps = append(cur.deps, uvDependencyNames(depsText.String())...)
		depsText.Reset()
		collectingDeps = false
		bracket = 0
	}

	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)

	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		raw := sc.Text()
		line := strings.TrimSpace(raw)

		if collectingDeps {
			depsText.WriteString(raw)
			depsText.WriteByte('\n')
			bracket += strings.Count(raw, "[") - strings.Count(raw, "]")
			if bracket <= 0 {
				finishDeps()
			}
			continue
		}

		switch {
		case line == "[[package]]":
			flush()
			inPackage = true

		case strings.HasPrefix(line, "["):
			flush()
			inPackage = false

		case inPackage:
			key, value, ok := uvTOMLAssignment(line)
			if !ok {
				continue
			}

			switch key {
			case "name":
				cur.name = tomlString(value)
			case "version":
				cur.version = tomlString(value)
			case "source":
				cur.registry = uvRegistrySource(value)
			case "dependencies":
				// value begins with '['; a single-line array closes immediately, otherwise accumulate.
				depsText.Reset()
				depsText.WriteString(value)
				depsText.WriteByte('\n')
				bracket = strings.Count(value, "[") - strings.Count(value, "]")
				if bracket <= 0 {
					finishDeps()
				} else {
					collectingDeps = true
				}
			}
		}
	}
	flush()

	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan uv.lock: %w", err)
	}

	// Pass 2: index emitted components by name, then emit components + resolved edges. A name mapping to more
	// than one emitted version is ambiguous (universal lock) and resolves to NO edge, never a guessed target.
	purlOf := func(name, version string) string { return "pkg:pypi/" + name + "@" + version }
	versionsOf := map[string][]string{}
	emitted := func(p uvPackage) (string, bool) {
		name := normalizePyPI(strings.TrimSpace(p.name))
		version := strings.TrimSpace(p.version)
		if !p.registry || name == "" || !sbom.IsResolvedVersion(version) {
			return "", false
		}
		return name, true
	}
	for _, p := range pkgs {
		if name, ok := emitted(p); ok {
			versionsOf[name] = append(versionsOf[name], strings.TrimSpace(p.version))
		}
	}

	set := newComponentSet()
	var deps []sbom.Dependency
	for _, p := range pkgs {
		name, ok := emitted(p)
		if !ok {
			continue
		}
		version := strings.TrimSpace(p.version)
		ref := purlOf(name, version)
		set.add(sbom.Component{Name: name, Version: version, PURL: ref, Location: in.Path, Scope: scope})

		seen := map[string]bool{ref: true} // drop self-edges + duplicate targets
		var on []string
		for _, d := range p.deps {
			dn := normalizePyPI(strings.TrimSpace(d))
			vs := versionsOf[dn]
			if len(vs) != 1 {
				continue // not an emitted component, or an ambiguous duplicate name – no edge
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

	comps := set.components()
	sort.Slice(comps, func(i, j int) bool {
		return comps[i].PURL < comps[j].PURL
	})
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })

	return comps, deps, nil
}
