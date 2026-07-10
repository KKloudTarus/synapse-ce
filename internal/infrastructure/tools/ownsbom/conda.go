package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Conda is the owned Conda parser: it reads an environment.yml dependencies list into Conda components,
// plus PyPI components for exact requirements nested under `pip:`. environment.yml is a declaration rather
// than a solver lock, so plain/ranged Conda entries remain visible without a resolved version. Hand-parsed as
// a small indented YAML subset, with no third-party YAML or scanner dependency. Components only; edges deferred.
type Conda struct{}

// Ecosystem identifies this parser's primary package ecosystem.
func (Conda) Ecosystem() string { return "conda" }

// Markers are the conventional Conda environment manifest basenames.
func (Conda) Markers() []string { return []string{"environment.yml", "environment.yaml"} }

// Parse extracts direct Conda dependencies and exact pip pins nested below a `- pip:` entry.
func (Conda) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	scope := sbom.ClassifyScope(in.Path, "")
	seen := map[string]bool{}
	var comps []sbom.Component
	add := func(c sbom.Component) {
		if c.Name == "" || c.PURL == "" || seen[c.PURL] {
			return
		}
		seen[c.PURL] = true
		comps = append(comps, c)
	}

	inDependencies := false
	inPip := false
	dependencyIndent := -1
	pipIndent := -1
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		raw := stripYAMLComment(sc.Text())
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		indent := leadingIndent(raw)
		if !inDependencies {
			if indent == 0 && trimmed == "dependencies:" {
				inDependencies = true
			}
			continue
		}
		if indent == 0 && !strings.HasPrefix(trimmed, "-") {
			break // the next top-level key ends dependencies; an indentationless sequence item remains valid YAML
		}
		if !strings.HasPrefix(trimmed, "-") {
			continue
		}

		if dependencyIndent < 0 {
			dependencyIndent = indent
		}
		if inPip && indent > pipIndent {
			if c, ok := pipComponent(yamlListScalar(trimmed), in.Path, scope); ok {
				add(c)
			}
			continue
		}
		if inPip && indent <= pipIndent {
			inPip = false
		}
		if indent != dependencyIndent {
			continue
		}

		spec := yamlListScalar(trimmed)
		if spec == "pip:" {
			inPip = true
			pipIndent = indent
			continue
		}
		if c, ok := condaComponent(spec, in.Path, scope); ok {
			add(c)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan environment.yml: %w", err)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, nil, nil
}

func condaComponent(spec, location, scope string) (sbom.Component, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.ContainsAny(spec, "{}[]") {
		return sbom.Component{}, false
	}
	channel := ""
	if before, after, ok := strings.Cut(spec, "::"); ok {
		channel, spec = normalizeCondaQualifier(before), strings.TrimSpace(after)
		if channel == "" || strings.Contains(spec, "::") {
			return sbom.Component{}, false
		}
	}
	nameEnd := strings.IndexAny(spec, "=<>!~")
	if nameEnd < 0 {
		name := normalizeCondaName(spec)
		return unresolvedConda(name, channel, location, scope)
	}
	name := normalizeCondaName(spec[:nameEnd])
	if name == "" {
		return sbom.Component{}, false
	}
	if spec[nameEnd] != '=' || strings.ContainsAny(spec[nameEnd:], "<>!~") {
		return unresolvedConda(name, channel, location, scope)
	}

	rest := strings.TrimSpace(spec[nameEnd+1:])
	if strings.HasPrefix(rest, "=") { // tolerate Conda's exact `name==version` form
		rest = strings.TrimSpace(rest[1:])
	}
	parts := strings.SplitN(rest, "=", 2)
	version := strings.TrimSpace(parts[0])
	if !sbom.IsResolvedVersion(version) || strings.ContainsAny(version, "*?,| \t") {
		return unresolvedConda(name, channel, location, scope)
	}
	purl := "pkg:conda/" + name + "@" + version
	qualifiers := make([]string, 0, 2)
	if len(parts) == 2 {
		build := normalizeCondaQualifier(parts[1])
		if build == "" || strings.Contains(parts[1], "=") {
			return sbom.Component{}, false
		}
		qualifiers = append(qualifiers, "build="+url.QueryEscape(build))
	}
	if channel != "" {
		qualifiers = append(qualifiers, "channel="+url.QueryEscape(channel))
	}
	if len(qualifiers) > 0 {
		purl += "?" + strings.Join(qualifiers, "&")
	}
	return sbom.Component{Name: name, Version: version, PURL: purl, Location: location, Scope: scope}, true
}

func unresolvedConda(name, channel, location, scope string) (sbom.Component, bool) {
	if name == "" {
		return sbom.Component{}, false
	}
	purl := "pkg:conda/" + name
	if channel != "" {
		purl += "?channel=" + url.QueryEscape(channel)
	}
	return sbom.Component{Name: name, PURL: purl, Location: location, Scope: scope}, true
}

func normalizeCondaName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || strings.ContainsAny(name, " /\\:@#?") {
		return ""
	}
	return name
}

func normalizeCondaQualifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, " /\\:@#?&=") {
		return ""
	}
	return value
}

func pipComponent(spec, location, scope string) (sbom.Component, bool) {
	if i := strings.IndexByte(spec, ';'); i >= 0 {
		spec = strings.TrimSpace(spec[:i])
	}
	eq := strings.Index(spec, "==")
	if eq < 0 {
		return sbom.Component{}, false
	}
	name := strings.TrimSpace(spec[:eq])
	if b := strings.IndexByte(name, '['); b >= 0 {
		name = strings.TrimSpace(name[:b])
	}
	version := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(spec[eq+2:]), "="))
	if j := strings.IndexAny(version, " \t,"); j >= 0 {
		version = version[:j]
	}
	if name == "" || !sbom.IsResolvedVersion(version) {
		return sbom.Component{}, false
	}
	name = normalizePyPI(name)
	return sbom.Component{Name: name, Version: version, PURL: "pkg:pypi/" + name + "@" + version, Location: location, Scope: scope}, true
}

func yamlListScalar(line string) string {
	scalar := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
	if len(scalar) >= 2 && ((scalar[0] == '"' && scalar[len(scalar)-1] == '"') || (scalar[0] == '\'' && scalar[len(scalar)-1] == '\'')) {
		return strings.TrimSpace(scalar[1 : len(scalar)-1])
	}
	return scalar
}

func stripYAMLComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'', '"':
			if quote == 0 {
				quote = line[i]
			} else if quote == line[i] && (line[i] == '\'' || i == 0 || line[i-1] != '\\') {
				quote = 0
			}
		case '#':
			if quote == 0 && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return line
}
