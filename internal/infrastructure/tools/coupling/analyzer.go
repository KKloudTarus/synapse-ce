// Package coupling builds deterministic first-party source dependency evidence.
// It parses source and metadata only; it never executes project code, a compiler,
// a package manager, a shell, or a network client.
package coupling

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFiles      = 50_000
	maxModules    = 50_000
	maxFileBytes  = 2 << 20
	maxTotalBytes = 512 << 20
	maxEdges      = 250_000
	maxGaps       = 4_096
)

type Analyzer struct{ js ports.JSImportScanner }

var _ ports.CouplingAnalyzer = (*Analyzer)(nil)

func New(js ports.JSImportScanner) *Analyzer { return &Analyzer{js: js} }

type goModule struct{ root, name string }
type goPackage struct {
	path    string
	imports map[string]bool
}

func (a *Analyzer) AnalyzeCoupling(ctx context.Context, root string) (measure.CouplingReport, error) {
	if ctx == nil {
		return measure.CouplingReport{}, fmt.Errorf("%w: coupling context is required", shared.ErrValidation)
	}
	root = strings.TrimSpace(root)
	if root == "" {
		return measure.CouplingReport{}, fmt.Errorf("%w: coupling root is required", shared.ErrValidation)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return measure.CouplingReport{}, fmt.Errorf("%w: coupling root must be a readable directory", shared.ErrValidation)
	}

	var goFiles, modFiles []string
	hasJS := false
	files, totalBytes := 0, int64(0)
	gaps := make([]measure.CouplingGap, 0)
	addGap := func(language, rel, reason string) {
		if len(gaps) < maxGaps {
			gaps = append(gaps, measure.CouplingGap{Language: language, Path: rel, Reason: reason})
		}
	}
	err = filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, filename)
		if relErr != nil {
			return fmt.Errorf("coupling: derive relative path")
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			rel = ""
		}
		if walkErr != nil {
			addGap("source", rel, "unreadable_entry")
			return nil
		}
		if entry.IsDir() {
			if rel != "" && skippedDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if supportedPath(rel) {
				addGap(languageForPath(rel), rel, "symlink_source")
			}
			return nil
		}
		lower := strings.ToLower(rel)
		if path.Base(lower) == "go.mod" {
			modFiles = append(modFiles, rel)
			return nil
		}
		if !supportedPath(lower) {
			return nil
		}
		files++
		if files > maxFiles {
			addGap("source", "", "file_budget_exceeded")
			return fs.SkipAll
		}
		fileInfo, infoErr := entry.Info()
		if infoErr != nil {
			addGap(languageForPath(rel), rel, "unreadable_source")
			return nil
		}
		if fileInfo.Size() > maxFileBytes {
			addGap(languageForPath(rel), rel, "file_too_large")
			return nil
		}
		totalBytes += fileInfo.Size()
		if totalBytes > maxTotalBytes {
			addGap("source", "", "byte_budget_exceeded")
			return fs.SkipAll
		}
		if strings.HasSuffix(lower, ".go") && !strings.HasSuffix(lower, "_test.go") {
			goFiles = append(goFiles, rel)
		}
		if isJSPath(lower) {
			hasJS = true
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return measure.CouplingReport{}, err
	}

	modules, edges := a.goEvidence(ctx, root, goFiles, modFiles, &gaps)
	if err := ctx.Err(); err != nil {
		return measure.CouplingReport{}, err
	}
	if hasJS {
		jsModules, jsEdges, jsGaps, jsErr := a.jsEvidence(ctx, root)
		if jsErr != nil {
			if ctx.Err() != nil {
				return measure.CouplingReport{}, ctx.Err()
			}
			addGap("js-ts", "", "scanner_unavailable")
		} else {
			modules = append(modules, jsModules...)
			edges = append(edges, jsEdges...)
			gaps = appendBounded(gaps, jsGaps...)
		}
	}
	sort.Slice(modules, func(i, j int) bool {
		if modules[i].ID != modules[j].ID {
			return modules[i].ID < modules[j].ID
		}
		return modules[i].Path < modules[j].Path
	})
	if len(modules) > maxModules {
		modules = modules[:maxModules]
		addGap("source", "", "module_budget_exceeded")
	}
	retained := make(map[string]bool, len(modules))
	for _, module := range modules {
		retained[module.ID] = true
	}
	edges = canonicalEdges(edges, retained)
	if len(edges) > maxEdges {
		edges = edges[:maxEdges]
		addGap("source", "", "edge_budget_exceeded")
	}
	return measure.NewCouplingReport(modules, edges, gaps)
}

func (a *Analyzer) goEvidence(ctx context.Context, root string, goFiles, modFiles []string, gaps *[]measure.CouplingGap) ([]measure.CouplingModule, []measure.CouplingEdge) {
	var roots []goModule
	for _, rel := range modFiles {
		if ctx.Err() != nil {
			break
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- path came from the confined walk
		if err != nil || len(data) > maxFileBytes {
			*gaps = appendBounded(*gaps, measure.CouplingGap{Language: "go", Path: rel, Reason: "unreadable_module_metadata"})
			continue
		}
		name := strings.TrimSpace(modfile.ModulePath(data))
		if name == "" {
			*gaps = appendBounded(*gaps, measure.CouplingGap{Language: "go", Path: rel, Reason: "malformed_module_metadata"})
			continue
		}
		dir := path.Dir(rel)
		if dir == "." {
			dir = ""
		}
		roots = append(roots, goModule{root: dir, name: name})
	}
	sort.Slice(roots, func(i, j int) bool { return len(roots[i].root) > len(roots[j].root) })

	packages := map[string]*goPackage{}
	for _, rel := range goFiles {
		if ctx.Err() != nil {
			break
		}
		dir := path.Dir(rel)
		if dir == "." {
			dir = ""
		}
		module, ok := containingGoModule(dir, roots)
		if !ok {
			*gaps = appendBounded(*gaps, measure.CouplingGap{Language: "go", Path: rel, Reason: "missing_module_metadata"})
			continue
		}
		pkgImport := module.name
		if suffix := strings.TrimPrefix(strings.TrimPrefix(dir, module.root), "/"); suffix != "" {
			pkgImport += "/" + suffix
		}
		pkg := packages[dir]
		if pkg == nil {
			pkg = &goPackage{path: pkgImport, imports: map[string]bool{}}
			packages[dir] = pkg
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- path came from the confined walk
		if err != nil {
			*gaps = appendBounded(*gaps, measure.CouplingGap{Language: "go", Path: rel, Reason: "unreadable_source"})
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), rel, data, parser.ImportsOnly)
		if err != nil {
			*gaps = appendBounded(*gaps, measure.CouplingGap{Language: "go", Path: rel, Reason: "malformed_source"})
			continue
		}
		for _, spec := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				*gaps = appendBounded(*gaps, measure.CouplingGap{Language: "go", Path: rel, Reason: "malformed_import"})
				continue
			}
			pkg.imports[importPath] = true
		}
	}

	byImport := map[string][]string{}
	var modules []measure.CouplingModule
	dirs := make([]string, 0, len(packages))
	for dir := range packages {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		pkg := packages[dir]
		id := "go:" + dir
		if dir == "" {
			id = "go:."
		}
		modules = append(modules, measure.CouplingModule{ID: id, Path: dir, Language: "go"})
		byImport[pkg.path] = append(byImport[pkg.path], id)
	}
	importPaths := make([]string, 0, len(byImport))
	for importPath := range byImport {
		importPaths = append(importPaths, importPath)
	}
	sort.Strings(importPaths)
	for _, importPath := range importPaths {
		if len(byImport[importPath]) > 1 {
			*gaps = appendBounded(*gaps, measure.CouplingGap{Language: "go", Reason: "ambiguous_module_import_path"})
		}
	}
	var edges []measure.CouplingEdge
	for _, dir := range dirs {
		pkg := packages[dir]
		fromIDs := byImport[pkg.path]
		if len(fromIDs) != 1 {
			continue
		}
		for _, imported := range sortedSetKeys(pkg.imports) {
			if toIDs := byImport[imported]; len(toIDs) == 1 {
				edges = append(edges, measure.CouplingEdge{From: fromIDs[0], To: toIDs[0]})
			}
		}
	}
	return modules, edges
}

func (a *Analyzer) jsEvidence(ctx context.Context, root string) ([]measure.CouplingModule, []measure.CouplingEdge, []measure.CouplingGap, error) {
	if a.js == nil {
		return nil, nil, nil, errors.New("js import scanner is not configured")
	}
	graph, err := a.js.Scan(ctx, root)
	if err != nil {
		return nil, nil, nil, err
	}
	byPath := map[string]string{}
	modules := make([]measure.CouplingModule, 0, len(graph.Modules))
	for _, module := range graph.Modules {
		id := "js-ts:" + module.Path
		byPath[module.Path] = id
		modules = append(modules, measure.CouplingModule{ID: id, Path: module.Path, Language: "js-ts"})
	}
	var edges []measure.CouplingEdge
	for _, edge := range graph.Edges {
		if edge.To != "" && byPath[edge.From] != "" && byPath[edge.To] != "" {
			edges = append(edges, measure.CouplingEdge{From: byPath[edge.From], To: byPath[edge.To]})
		}
	}
	var gaps []measure.CouplingGap
	for _, gap := range graph.Coverage {
		gaps = append(gaps, measure.CouplingGap{Language: "js-ts", Path: gap.Path, Reason: string(gap.Kind)})
	}
	return modules, edges, gaps, nil
}

func containingGoModule(dir string, modules []goModule) (goModule, bool) {
	for _, module := range modules {
		if dir == module.root || (module.root != "" && strings.HasPrefix(dir, module.root+"/")) || module.root == "" {
			return module, true
		}
	}
	return goModule{}, false
}

func appendBounded(gaps []measure.CouplingGap, items ...measure.CouplingGap) []measure.CouplingGap {
	remaining := maxGaps - len(gaps)
	if remaining <= 0 {
		return gaps
	}
	if len(items) > remaining {
		items = items[:remaining]
	}
	return append(gaps, items...)
}

func canonicalEdges(edges []measure.CouplingEdge, retained map[string]bool) []measure.CouplingEdge {
	unique := make(map[string]measure.CouplingEdge, len(edges))
	for _, edge := range edges {
		if edge.From == edge.To || !retained[edge.From] || !retained[edge.To] {
			continue
		}
		unique[edge.From+"\x00"+edge.To] = edge
	}
	out := make([]measure.CouplingEdge, 0, len(unique))
	for _, edge := range unique {
		out = append(out, edge)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

func sortedSetKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func skippedDirectory(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "coverage", ".next", ".cache":
		return true
	default:
		return false
	}
}
func isJSPath(p string) bool {
	ext := path.Ext(p)
	return ext == ".js" || ext == ".jsx" || ext == ".ts" || ext == ".tsx" || ext == ".mjs" || ext == ".cjs" || ext == ".mts" || ext == ".cts"
}
func supportedPath(p string) bool {
	return strings.HasSuffix(strings.ToLower(p), ".go") || isJSPath(strings.ToLower(p))
}
func languageForPath(p string) string {
	if strings.HasSuffix(strings.ToLower(p), ".go") {
		return "go"
	}
	return "js-ts"
}
