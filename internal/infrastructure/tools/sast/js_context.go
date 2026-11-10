package sast

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsimports"
)

// Match the existing import scanner's edge bound. Exhaustion retains baseline
// SSRF candidates rather than using an incomplete graph to suppress findings.
const maxJSContextEdges = 250_000

type jsRuntimeContext struct {
	server  map[string]bool
	browser map[string]bool
}

func buildJSRuntimeContext(ctx context.Context, files []sourceFile, edgeLimit int) (jsRuntimeContext, error) {
	server := make(map[string]bool)
	browserInput := false
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return jsRuntimeContext{}, err
		}
		if jsExts[f.Ext] {
			server[f.Rel] = false
		}
		browserInput = browserInput || f.Ext == ".html" || f.Ext == ".htm"
	}
	metadata := jsImportMetadata{}
	if browserInput {
		var err error
		metadata, err = jsRuntimeMetadata(ctx, files)
		if err != nil {
			return jsRuntimeContext{}, err
		}
	}
	complete := metadata.complete
	dependencies := make(map[string][]string)
	runtime := make(map[string]bool)
	importers := make(map[string][]string)
	var queue []string
	edges := 0
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return jsRuntimeContext{}, err
		}
		if !jsExts[f.Ext] {
			continue
		}
		server[f.Rel] = jsRequestContextFile(f.Lines)
		jsxAware := f.Ext != ".ts" && f.Ext != ".mts" && f.Ext != ".cts"
		imports, observed, err := jsimports.ObserveSourceImports(ctx, []byte(strings.Join(f.Lines, "\n")), jsxAware)
		if err != nil {
			return jsRuntimeContext{}, err
		}
		possibleNode := !observed
		complete = complete && observed
		seen := make(map[string]bool)
		for _, imp := range imports {
			if err := ctx.Err(); err != nil {
				return jsRuntimeContext{}, err
			}
			if imp.TypeOnly {
				continue
			}
			if jsresolution.ClassifySpecifier(imp.Specifier).Kind == jsresolution.SpecifierBuiltin {
				possibleNode = true
			}
			candidate, known := jsRuntimeImportTarget(f.Rel, imp.Specifier, server, metadata)
			complete = complete && known
			if candidate == "" || seen[candidate] {
				continue
			}
			if edges >= edgeLimit {
				for rel := range server {
					server[rel] = true
				}
				return jsRuntimeContext{server: server}, ctx.Err()
			}
			importers[candidate] = append(importers[candidate], f.Rel)
			dependencies[f.Rel] = append(dependencies[f.Rel], candidate)
			seen[candidate] = true
			edges++
		}
		if possibleNode {
			runtime[f.Rel] = true
			server[f.Rel] = true
			queue = append(queue, f.Rel)
		}
	}
	for at := 0; at < len(queue); at++ {
		if err := ctx.Err(); err != nil {
			return jsRuntimeContext{}, err
		}
		for _, importer := range importers[queue[at]] {
			if !runtime[importer] {
				runtime[importer] = true
				server[importer] = true
				queue = append(queue, importer)
			}
		}
	}
	result := jsRuntimeContext{server: server}
	if !complete {
		return result, nil
	}
	entries, err := jsHTMLModuleEntries(ctx, files, server, metadata)
	if err != nil {
		return jsRuntimeContext{}, err
	}
	if len(entries) == 0 {
		return result, nil
	}
	browser, err := jsForwardClosure(ctx, entries, dependencies)
	if err != nil {
		return jsRuntimeContext{}, err
	}
	conflicts := make(map[string]bool)
	for rel, isServer := range server {
		if isServer || !browser[rel] {
			conflicts[rel] = true
		}
	}
	conflict, err := jsForwardClosure(ctx, conflicts, dependencies)
	if err != nil {
		return jsRuntimeContext{}, err
	}
	result.browser = make(map[string]bool)
	for rel := range browser {
		if !conflict[rel] {
			result.browser[rel] = true
		}
	}
	return result, nil
}
