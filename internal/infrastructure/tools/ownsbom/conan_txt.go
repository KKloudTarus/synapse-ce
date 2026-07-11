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

// parseConanTxt parses the conanfile.txt manifest. It supports exact dependencies under
// [requires], [tool_requires], and [test_requires] sections. Version ranges and
// unknown sections are safely ignored. It is fail-soft for individual malformed lines
// but fail-loud on IO or scanner errors.
func parseConanTxt(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	set := newComponentSet()
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)

	dirScope := sbom.ClassifyScope(in.Path, "") // path scope is invariant across sections
	var currentScope string

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		// Handle comments properly: only treat '#' as comment if it's at the start or preceded by whitespace.
		// Conan uses '#' for recipe revisions (e.g., zlib/1.2.13#revision), which must not be truncated here.
		if strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, "\t#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.ToLower(line[1 : len(line)-1])

			switch section {
			case "requires":
				currentScope = dirScope // path defaults
			case "tool_requires":
				if sbom.IsBackgroundScope(dirScope) {
					currentScope = dirScope
				} else {
					currentScope = sbom.ScopeDevelopment
				}
			case "test_requires":
				currentScope = sbom.ScopeTest
			default:
				currentScope = "" // entering an ignored section
			}
			continue
		}

		if currentScope != "" {
			// Ignore version ranges (e.g., poco/[>1.0 <2.0]). SBOM needs resolved versions.
			if strings.ContainsAny(line, "[<>~^]") {
				continue
			}

			name, version := parseConanRef(line)
			if name == "" || version == "" {
				continue // skip malformed lines fail-soft
			}

			set.add(sbom.Component{
				Name:     name,
				Version:  version,
				PURL:     "pkg:conan/" + name + "@" + version,
				Location: in.Path,
				Scope:    currentScope,
			})
		}
	}

	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan conanfile.txt: %w", err)
	}

	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, nil, nil
}
