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

// UV is the owned Python-via-uv parser. It reads registry-backed packages
// from uv.lock [[package]] blocks and emits normalized PyPI components.
//
// Only packages with a non-empty name, concrete resolved version, and
// canonical registry source are emitted. Local, editable, virtual, Git, and
// direct-URL package sources are skipped. Dependency edges are intentionally
// deferred because uv's universal lock can require source, version, and marker
// disambiguation.
//
// The parser targets uv's canonical generated TOML layout, uses only the Go
// standard library, and performs no network or external-command execution.
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

// Parse extracts resolved registry packages from a uv.lock file as
// deterministic PyPI components.
func (UV) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	scope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()

	var cur uvPackage
	inPackage := false

	flush := func() {
		if !inPackage {
			return
		}

		name := normalizePyPI(strings.TrimSpace(cur.name))
		version := strings.TrimSpace(cur.version)

		if cur.registry && name != "" && sbom.IsResolvedVersion(version) {
			set.add(sbom.Component{
				Name:     name,
				Version:  version,
				PURL:     "pkg:pypi/" + name + "@" + version,
				Location: in.Path,
				Scope:    scope,
			})
		}

		cur = uvPackage{}
	}

	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)

	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		line := strings.TrimSpace(sc.Text())

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
			}
		}
	}

	flush()

	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan uv.lock: %w", err)
	}

	comps := set.components()
	sort.Slice(comps, func(i, j int) bool {
		return comps[i].PURL < comps[j].PURL
	})

	return comps, nil, nil
}
