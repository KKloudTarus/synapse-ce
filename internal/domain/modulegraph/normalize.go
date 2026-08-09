package modulegraph

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// NormalizeRepositoryPath converts a scanner path into the canonical
// repository-relative slash form and rejects absolute paths and root escapes.
func NormalizeRepositoryPath(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("modulegraph: empty repository path")
	}
	if strings.IndexByte(raw, 0) >= 0 {
		return "", fmt.Errorf("modulegraph: repository path contains NUL")
	}

	slashed := strings.ReplaceAll(raw, "\\", "/")
	if strings.HasPrefix(slashed, "/") || strings.HasPrefix(slashed, "//") || hasWindowsVolumePrefix(slashed) {
		return "", fmt.Errorf("modulegraph: absolute repository path %q", raw)
	}

	cleaned := path.Clean(slashed)
	if cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("modulegraph: repository path %q has no file component", raw)
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("modulegraph: repository path %q escapes the scan root", raw)
	}
	return strings.TrimPrefix(cleaned, "./"), nil
}

// Normalize validates, deduplicates, and deterministically sorts a graph. It
// returns a new graph and does not mutate the input. Structural roots are
// recomputed from resolved first-party edges.
func Normalize(in Graph) (Graph, error) {
	if in.FilesScanned < 0 {
		return Graph{}, fmt.Errorf("modulegraph: negative files scanned: %d", in.FilesScanned)
	}
	if in.BytesScanned < 0 {
		return Graph{}, fmt.Errorf("modulegraph: negative bytes scanned: %d", in.BytesScanned)
	}

	out := Graph{FilesScanned: in.FilesScanned, BytesScanned: in.BytesScanned}
	moduleByPath := make(map[string]Module, len(in.Modules))

	for _, module := range in.Modules {
		normalizedPath, err := NormalizeRepositoryPath(module.Path)
		if err != nil {
			return Graph{}, fmt.Errorf("normalize module %q: %w", module.Path, err)
		}
		dialect, ok := DialectForPath(normalizedPath)
		if !ok {
			return Graph{}, fmt.Errorf("modulegraph: unsupported source extension for %q", normalizedPath)
		}
		if !module.Dialect.Valid() || module.Dialect != dialect {
			return Graph{}, fmt.Errorf("modulegraph: dialect %q does not match %q", module.Dialect, normalizedPath)
		}
		declarationOnly := IsDeclarationPath(normalizedPath)
		if module.DeclarationOnly != declarationOnly {
			return Graph{}, fmt.Errorf("modulegraph: declaration-only flag does not match %q", normalizedPath)
		}

		normalized := Module{Path: normalizedPath, Dialect: module.Dialect, DeclarationOnly: module.DeclarationOnly}
		if previous, exists := moduleByPath[normalizedPath]; exists {
			if previous != normalized {
				return Graph{}, fmt.Errorf("modulegraph: conflicting duplicate module %q", normalizedPath)
			}
			continue
		}
		moduleByPath[normalizedPath] = normalized
	}

	out.Modules = make([]Module, 0, len(moduleByPath))
	for _, module := range moduleByPath {
		out.Modules = append(out.Modules, module)
	}
	sort.Slice(out.Modules, func(i, j int) bool { return out.Modules[i].Path < out.Modules[j].Path })

	out.Edges = make([]Edge, 0, len(in.Edges))
	for _, edge := range in.Edges {
		normalized, err := normalizeEdge(edge, moduleByPath)
		if err != nil {
			return Graph{}, err
		}
		out.Edges = append(out.Edges, normalized)
	}
	sort.Slice(out.Edges, func(i, j int) bool { return edgeLess(out.Edges[i], out.Edges[j]) })
	out.Edges = deduplicateEdges(out.Edges)

	out.Coverage = make([]CoverageIssue, 0, len(in.Coverage))
	for _, issue := range in.Coverage {
		if !issue.Kind.Valid() {
			return Graph{}, fmt.Errorf("modulegraph: invalid coverage issue kind %q", issue.Kind)
		}
		if issue.Line < 0 {
			return Graph{}, fmt.Errorf("modulegraph: negative coverage line for %q", issue.Path)
		}
		if issue.Path != "" {
			normalizedPath, err := NormalizeRepositoryPath(issue.Path)
			if err != nil {
				return Graph{}, fmt.Errorf("normalize coverage path %q: %w", issue.Path, err)
			}
			issue.Path = normalizedPath
		}
		out.Coverage = append(out.Coverage, issue)
	}
	sort.Slice(out.Coverage, func(i, j int) bool { return coverageLess(out.Coverage[i], out.Coverage[j]) })
	out.Coverage = deduplicateCoverage(out.Coverage)

	// Tier-2 symbol evidence is normalized like every other member. A use whose module is not a scanned
	// module is an error rather than a dropped record: silently discarding a reference is how a symbol
	// that IS reached comes to look unused.
	out.LocalUses = make([]LocalUse, 0, len(in.LocalUses))
	for _, use := range in.LocalUses {
		normalized, err := normalizeLocalUse(use, moduleByPath)
		if err != nil {
			return Graph{}, err
		}
		out.LocalUses = append(out.LocalUses, normalized)
	}
	sort.Slice(out.LocalUses, func(i, j int) bool { return localUseLess(out.LocalUses[i], out.LocalUses[j]) })
	out.LocalUses = deduplicateLocalUses(out.LocalUses)

	out.Roots = structuralRoots(out.Modules, out.Edges)

	return out, nil
}

func normalizeLocalUse(use LocalUse, modules map[string]Module) (LocalUse, error) {
	if !use.Kind.Valid() {
		return LocalUse{}, fmt.Errorf("modulegraph: invalid local use kind %q", use.Kind)
	}
	if use.Line < 0 {
		return LocalUse{}, fmt.Errorf("modulegraph: negative local use line in %q", use.Module)
	}
	if strings.TrimSpace(use.Local) == "" {
		return LocalUse{}, fmt.Errorf("modulegraph: local use in %q names no local", use.Module)
	}
	// A property use must name the property, and an opaque use must not: an opaque reference is exactly
	// one whose reached symbol is unknown, so carrying a property would misrepresent it as observed.
	if use.Kind == LocalUseProperty && strings.TrimSpace(use.Property) == "" {
		return LocalUse{}, fmt.Errorf("modulegraph: property use of %q names no property", use.Local)
	}
	if use.Kind == LocalUseOpaque && strings.TrimSpace(use.Property) != "" {
		return LocalUse{}, fmt.Errorf("modulegraph: opaque use of %q must not name a property", use.Local)
	}
	module, err := NormalizeRepositoryPath(use.Module)
	if err != nil {
		return LocalUse{}, fmt.Errorf("normalize local use module %q: %w", use.Module, err)
	}
	if _, ok := modules[module]; !ok {
		return LocalUse{}, fmt.Errorf("modulegraph: local use module %q is not a known module", module)
	}
	use.Module = module
	return use, nil
}

func localUseLess(a, b LocalUse) bool {
	if a.Module != b.Module {
		return a.Module < b.Module
	}
	if a.Local != b.Local {
		return a.Local < b.Local
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Property != b.Property {
		return a.Property < b.Property
	}
	if a.Detail != b.Detail {
		return a.Detail < b.Detail
	}
	return a.Line < b.Line
}

// deduplicateLocalUses collapses references that carry identical evidence, keeping the FIRST line so a
// reader is pointed at the earliest occurrence.
func deduplicateLocalUses(sorted []LocalUse) []LocalUse {
	if len(sorted) < 2 {
		return sorted
	}
	same := func(a, b LocalUse) bool {
		return a.Module == b.Module && a.Local == b.Local && a.Kind == b.Kind &&
			a.Property == b.Property && a.Detail == b.Detail
	}
	out := sorted[:1]
	for _, use := range sorted[1:] {
		if same(out[len(out)-1], use) {
			continue
		}
		out = append(out, use)
	}
	return out
}

func normalizeEdge(edge Edge, modules map[string]Module) (Edge, error) {
	if !edge.Kind.Valid() {
		return Edge{}, fmt.Errorf("modulegraph: invalid import kind %q", edge.Kind)
	}
	if edge.Position.Line < 0 || edge.Position.Column < 0 {
		return Edge{}, fmt.Errorf("modulegraph: negative source position for edge from %q", edge.From)
	}

	from, err := NormalizeRepositoryPath(edge.From)
	if err != nil {
		return Edge{}, fmt.Errorf("normalize edge source %q: %w", edge.From, err)
	}
	if _, ok := modules[from]; !ok {
		return Edge{}, fmt.Errorf("modulegraph: edge source %q is not a known module", from)
	}
	edge.From = from

	if edge.To != "" {
		to, err := NormalizeRepositoryPath(edge.To)
		if err != nil {
			return Edge{}, fmt.Errorf("normalize edge target %q: %w", edge.To, err)
		}
		if _, ok := modules[to]; !ok {
			return Edge{}, fmt.Errorf("modulegraph: edge target %q is not a known module", to)
		}
		edge.To = to
	}

	edge.Bindings = append([]Binding(nil), edge.Bindings...)
	sort.Slice(edge.Bindings, func(i, j int) bool { return bindingLess(edge.Bindings[i], edge.Bindings[j]) })
	edge.Bindings = deduplicateBindings(edge.Bindings)
	return edge, nil
}

func structuralRoots(modules []Module, edges []Edge) []string {
	incoming := make(map[string]bool, len(modules))
	for _, edge := range edges {
		if edge.To != "" {
			incoming[edge.To] = true
		}
	}
	roots := make([]string, 0, len(modules))
	for _, module := range modules {
		if !incoming[module.Path] {
			roots = append(roots, module.Path)
		}
	}
	return roots
}

func hasWindowsVolumePrefix(p string) bool {
	return len(p) >= 2 && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) && p[1] == ':'
}

func bindingLess(a, b Binding) bool {
	if a.Imported != b.Imported {
		return a.Imported < b.Imported
	}
	if a.Local != b.Local {
		return a.Local < b.Local
	}
	if a.Default != b.Default {
		return !a.Default && b.Default
	}
	if a.Namespace != b.Namespace {
		return !a.Namespace && b.Namespace
	}
	if a.TypeOnly != b.TypeOnly {
		return !a.TypeOnly && b.TypeOnly
	}
	return false
}

func edgeLess(a, b Edge) bool {
	if a.From != b.From {
		return a.From < b.From
	}
	if a.To != b.To {
		return a.To < b.To
	}
	if a.Specifier != b.Specifier {
		return a.Specifier < b.Specifier
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.TypeOnly != b.TypeOnly {
		return !a.TypeOnly && b.TypeOnly
	}
	if a.Position.Line != b.Position.Line {
		return a.Position.Line < b.Position.Line
	}
	if a.Position.Column != b.Position.Column {
		return a.Position.Column < b.Position.Column
	}
	return bindingsLess(a.Bindings, b.Bindings)
}

func bindingsLess(a, b []Binding) bool {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] == b[i] {
			continue
		}
		return bindingLess(a[i], b[i])
	}
	return len(a) < len(b)
}

func coverageLess(a, b CoverageIssue) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Detail < b.Detail
}

func deduplicateBindings(values []Binding) []Binding {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func deduplicateEdges(values []Edge) []Edge {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if !edgesEqual(value, result[len(result)-1]) {
			result = append(result, value)
		}
	}
	return result
}

func deduplicateCoverage(values []CoverageIssue) []CoverageIssue {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func edgesEqual(a, b Edge) bool {
	if a.From != b.From || a.To != b.To || a.Specifier != b.Specifier || a.Kind != b.Kind || a.TypeOnly != b.TypeOnly || a.Position != b.Position {
		return false
	}
	if len(a.Bindings) != len(b.Bindings) {
		return false
	}
	for i := range a.Bindings {
		if a.Bindings[i] != b.Bindings[i] {
			return false
		}
	}
	return true
}
