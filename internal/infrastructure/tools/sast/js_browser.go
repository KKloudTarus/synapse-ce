package sast

import (
	"context"
	"encoding/json"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsimports"
)

type jsImportMetadata struct {
	aliases  map[string][]jsimports.ViteAlias
	packages map[string]map[string]string
	local    map[string]bool
	complete bool
}

func jsRuntimeMetadata(ctx context.Context, files []sourceFile) (jsImportMetadata, error) {
	m := jsImportMetadata{aliases: make(map[string][]jsimports.ViteAlias), packages: make(map[string]map[string]string), local: make(map[string]bool), complete: true}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return m, err
		}
		dir := path.Dir(f.Rel)
		if path.Base(f.Rel) == "package.json" {
			var pkg struct {
				Name            string
				Dependencies    map[string]string
				DevDependencies map[string]string
			}
			if json.Unmarshal([]byte(strings.Join(f.Lines, "\n")), &pkg) != nil {
				m.complete = false
				continue
			}
			m.local[pkg.Name] = true
			if pkg.Dependencies == nil {
				pkg.Dependencies = make(map[string]string)
			}
			for name, version := range pkg.DevDependencies {
				pkg.Dependencies[name] = version
			}
			m.packages[dir] = pkg.Dependencies
		}
		if !strings.HasPrefix(path.Base(f.Rel), "vite.config.") {
			continue
		}
		if _, exists := m.aliases[dir]; exists {
			m.complete = false
			continue
		}
		aliases, complete, err := jsimports.ObserveViteAliases(ctx, []byte(strings.Join(f.Lines, "\n")))
		if err != nil {
			return m, err
		}
		m.complete = m.complete && complete
		for i := range aliases {
			if f.Path == "" || !filepath.IsAbs(aliases[i].Replacement) {
				m.complete = false
				continue
			}
			root, err := filepath.Abs(strings.TrimSuffix(f.Path, filepath.FromSlash(f.Rel)))
			if err != nil {
				m.complete = false
				continue
			}
			rel, err := filepath.Rel(root, aliases[i].Replacement)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				m.complete = false
				continue
			}
			aliases[i].Replacement = filepath.ToSlash(rel)
		}
		m.aliases[dir] = aliases
	}
	return m, nil
}

func jsRuntimeImportTarget(from, specifier string, modules map[string]bool, metadata jsImportMetadata) (string, bool) {
	if at := strings.IndexAny(specifier, "?#"); at >= 0 {
		specifier = specifier[:at]
	}
	if base, aliased := jsRuntimeAliasBase(from, specifier, metadata); aliased {
		if jsimports.IsAssetSpecifier(base) {
			return "", true
		}
		return jsRuntimeModuleTarget(base, modules)
	}
	if strings.HasPrefix(specifier, ".") {
		if jsimports.IsAssetSpecifier(specifier) {
			return "", true
		}
		return jsRuntimeModuleTarget(path.Join(path.Dir(from), specifier), modules)
	}
	classified := jsresolution.ClassifySpecifier(specifier)
	if classified.Kind == jsresolution.SpecifierBuiltin {
		return "", true
	}
	if classified.Kind != jsresolution.SpecifierPackage || metadata.local[classified.PackageName] {
		return "", false
	}
	for dir := path.Dir(from); ; dir = path.Dir(dir) {
		if packages, exists := metadata.packages[dir]; exists {
			version := packages[classified.PackageName]
			return "", version != "" && !strings.HasPrefix(version, "workspace:") && !strings.HasPrefix(version, "file:") && !strings.HasPrefix(version, "link:")
		}
		if dir == "." {
			return "", false
		}
	}
}

func jsRuntimeAliasBase(from, specifier string, metadata jsImportMetadata) (string, bool) {
	for dir := path.Dir(from); ; dir = path.Dir(dir) {
		if aliases, exists := metadata.aliases[dir]; exists {
			for _, alias := range aliases {
				if specifier == alias.Find || strings.HasPrefix(specifier, alias.Find+"/") {
					return alias.Replacement + strings.TrimPrefix(specifier, alias.Find), true
				}
			}
			break
		}
		if dir == "." {
			break
		}
	}
	return "", false
}

func jsRuntimeModuleTarget(base string, modules map[string]bool) (string, bool) {
	for _, candidate := range jsresolution.ModuleFileCandidates(path.Clean(base)) {
		if _, exists := modules[candidate]; exists {
			return candidate, true
		}
	}
	return "", false
}

func jsHTMLModuleEntries(ctx context.Context, files []sourceFile, modules map[string]bool, metadata jsImportMetadata) (map[string]bool, error) {
	entries := make(map[string]bool)
	for _, f := range files {
		if f.Ext != ".html" && f.Ext != ".htm" {
			continue
		}
		document, err := html.Parse(strings.NewReader(strings.Join(f.Lines, "\n")))
		if err != nil {
			return nil, nil
		}
		pending := []*html.Node{document}
		for len(pending) > 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			node := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			if node.Type == html.ElementNode && node.Namespace == "" && node.Data == "base" {
				for _, attr := range node.Attr {
					if attr.Key == "href" && attr.Val != "" {
						return nil, nil
					}
				}
			}
			if node.Type == html.ElementNode && (node.Data == "template" || node.Data == "noscript" || node.Data == "iframe") {
				continue
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				pending = append(pending, child)
			}
			if node.Type != html.ElementNode || node.Namespace != "" || node.Data != "script" {
				continue
			}
			var source, scriptType string
			var seenSource, seenType bool
			for _, attr := range node.Attr {
				if attr.Key == "src" && !seenSource {
					source = attr.Val
					seenSource = true
				} else if attr.Key == "type" && !seenType {
					scriptType = attr.Val
					seenType = true
				}
			}
			if scriptType != "module" || source == "" || strings.Contains(source, ":") || strings.HasPrefix(source, "//") {
				continue
			}
			if at := strings.IndexAny(source, "?#"); at >= 0 {
				source = source[:at]
			}
			base := path.Join(path.Dir(f.Rel), strings.TrimPrefix(source, "/"))
			if strings.HasPrefix(source, "/") {
				base = strings.TrimPrefix(source, "/")
			}
			if aliased, found := jsRuntimeAliasBase(f.Rel, source, metadata); found {
				base = aliased
			}
			if target, found := jsRuntimeModuleTarget(base, modules); found {
				entries[target] = true
			}
		}
	}
	return entries, nil
}

func jsForwardClosure(ctx context.Context, seeds map[string]bool, dependencies map[string][]string) (map[string]bool, error) {
	reached := make(map[string]bool, len(seeds))
	var queue []string
	for rel := range seeds {
		reached[rel] = true
		queue = append(queue, rel)
	}
	for at := 0; at < len(queue); at++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, dependency := range dependencies[queue[at]] {
			if !reached[dependency] {
				reached[dependency] = true
				queue = append(queue, dependency)
			}
		}
	}
	return reached, nil
}
