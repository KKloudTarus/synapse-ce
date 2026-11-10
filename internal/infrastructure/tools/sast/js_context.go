package sast

import (
	"context"
	"path"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsimports"
)

// Match the existing import scanner's edge bound. Exhaustion retains baseline
// SSRF candidates rather than using an incomplete graph to suppress findings.
const maxJSContextEdges = 250_000

// buildJSServerRequestFiles resolves only retained source. Node HTTP imports and
// uncertain module loads propagate to importers; request cues stay file-local.
// Preparation is O(source bytes + files + edges), with at most 100k source units
// and maxJSContextEdges retained edges. Each runtime seed is queued once.
func buildJSServerRequestFiles(ctx context.Context, files []sourceFile, edgeLimit int) (map[string]bool, error) {
	server := make(map[string]bool)
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if jsExts[f.Ext] {
			server[f.Rel] = false
		}
	}
	runtime := make(map[string]bool)
	importers := make(map[string][]string)
	var queue []string
	edges := 0
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !jsExts[f.Ext] {
			continue
		}
		server[f.Rel] = jsRequestContextFile(f.Lines)
		jsxAware := f.Ext != ".ts" && f.Ext != ".mts" && f.Ext != ".cts"
		imports, complete, err := jsimports.ObserveSourceImports(ctx, []byte(strings.Join(f.Lines, "\n")), jsxAware)
		if err != nil {
			return nil, err
		}
		possibleNode := !complete
		seen := make(map[string]bool)
		for _, imp := range imports {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if imp.TypeOnly {
				continue
			}
			switch imp.Specifier {
			case "http", "https", "node:http", "node:https":
				possibleNode = true
			}
			if !strings.HasPrefix(imp.Specifier, ".") {
				continue
			}
			specifier := imp.Specifier
			if at := strings.IndexAny(specifier, "?#"); at >= 0 {
				specifier = specifier[:at]
			}
			for _, candidate := range jsresolution.ModuleFileCandidates(path.Join(path.Dir(f.Rel), specifier)) {
				if _, exists := server[candidate]; !exists {
					continue
				}
				if !seen[candidate] {
					if edges >= edgeLimit {
						for rel := range server {
							server[rel] = true
						}
						return server, ctx.Err()
					}
					importers[candidate] = append(importers[candidate], f.Rel)
					seen[candidate] = true
					edges++
				}
				break
			}
		}
		if possibleNode {
			runtime[f.Rel] = true
			server[f.Rel] = true
			queue = append(queue, f.Rel)
		}
	}
	for at := 0; at < len(queue); at++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, importer := range importers[queue[at]] {
			if !runtime[importer] {
				runtime[importer] = true
				server[importer] = true
				queue = append(queue, importer)
			}
		}
	}
	return server, nil
}
