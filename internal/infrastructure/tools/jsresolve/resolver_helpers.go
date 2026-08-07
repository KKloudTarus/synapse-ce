package jsresolve

import (
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

// packageContextForImporter finds the nearest observed package.json boundary.
// contexts are normalized and sorted by scopeDir by aliasInventoryBuilder, so
// each ancestor lookup is logarithmic instead of scanning every package scope
// for every import edge.
func packageContextForImporter(contexts []aliasPackageContext, importer string) (aliasPackageContext, bool) {
	for scope := repositoryDirectory(importer); ; {
		if context, ok := packageContextAtScope(contexts, scope); ok {
			return context, true
		}
		parent, ok := parentRepositoryLocation(scope)
		if !ok {
			return aliasPackageContext{}, false
		}
		scope = parent
	}
}

func packageContextAtScope(contexts []aliasPackageContext, scope string) (aliasPackageContext, bool) {
	i := sort.Search(len(contexts), func(i int) bool { return contexts[i].scopeDir >= scope })
	if i < len(contexts) && contexts[i].scopeDir == scope {
		return contexts[i], true
	}
	return aliasPackageContext{}, false
}

// packageForRepositoryTarget finds the deepest package containing target.
// Inventory packages are normalized and sorted by Path, so walking the finite
// ancestor chain and binary-searching exact roots avoids an edge×package scan.
func packageForRepositoryTarget(packages []jsresolution.PackageMetadata, target string) (jsresolution.PackageMetadata, bool) {
	for candidate := target; ; {
		if pkg, ok := packageAtPath(packages, candidate); ok {
			return pkg, true
		}
		parent, ok := parentRepositoryLocation(candidate)
		if !ok {
			return jsresolution.PackageMetadata{}, false
		}
		candidate = parent
	}
}

func packageAtPath(packages []jsresolution.PackageMetadata, target string) (jsresolution.PackageMetadata, bool) {
	i := sort.Search(len(packages), func(i int) bool { return packages[i].Path >= target })
	if i < len(packages) && packages[i].Path == target {
		return packages[i], true
	}
	return jsresolution.PackageMetadata{}, false
}

func packageMetadataIdentity(pkg jsresolution.PackageMetadata) jsresolution.PackageIdentity {
	return jsresolution.PackageIdentity{
		Name: pkg.Name, Version: pkg.Version, Workspace: pkg.Workspace, Path: pkg.Path,
	}
}

func pathWithin(scope, candidate string) bool {
	if scope == "" || scope == "." {
		return candidate != "" && candidate != ".." && !strings.HasPrefix(candidate, "../")
	}
	return candidate == scope || strings.HasPrefix(candidate, scope+"/")
}

func containsPathSegment(value, segment string) bool {
	for _, part := range strings.Split(value, "/") {
		if part == segment {
			return true
		}
	}
	return false
}

func repositorySegmentCount(value string) int {
	if value == "" {
		return 0
	}
	return 1 + strings.Count(value, "/") + strings.Count(value, "\\")
}

func repositoryDirectory(value string) string {
	if slash := strings.LastIndexByte(value, '/'); slash >= 0 {
		if slash == 0 {
			return "."
		}
		return value[:slash]
	}
	return "."
}

func parentRepositoryLocation(value string) (string, bool) {
	if value == "" || value == "." {
		return "", false
	}
	if slash := strings.LastIndexByte(value, '/'); slash >= 0 {
		if slash == 0 {
			return ".", true
		}
		return value[:slash], true
	}
	return ".", true
}

// relativeEdgeHasCoverage performs at most one binary search for each relevant
// coverage kind. modulegraph.Normalize orders coverage by kind, path and line,
// so unresolved relative edges do not create an edge×coverage scan.
func relativeEdgeHasCoverage(coverage []modulegraph.CoverageIssue, edge modulegraph.Edge) bool {
	for _, kind := range [...]modulegraph.CoverageIssueKind{
		modulegraph.CoverageUnresolvedRelativeImport,
		modulegraph.CoverageAmbiguousRelativeImport,
		modulegraph.CoverageRelativeImportEscapesRoot,
	} {
		line := 0
		if edge.Position.Line > 0 {
			line = edge.Position.Line
		}
		i := sort.Search(len(coverage), func(i int) bool {
			issue := coverage[i]
			if issue.Kind != kind {
				return issue.Kind > kind
			}
			if issue.Path != edge.From {
				return issue.Path > edge.From
			}
			return issue.Line >= line
		})
		if i >= len(coverage) {
			continue
		}
		issue := coverage[i]
		if issue.Kind != kind || issue.Path != edge.From {
			continue
		}
		if edge.Position.Line <= 0 || issue.Line == edge.Position.Line {
			return true
		}
	}
	return false
}

func identityLess(a, b jsresolution.PackageIdentity) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.PURL != b.PURL {
		return a.PURL < b.PURL
	}
	if a.Workspace != b.Workspace {
		return !a.Workspace && b.Workspace
	}
	return a.Path < b.Path
}

func deduplicatePackageIdentities(in []jsresolution.PackageIdentity) []jsresolution.PackageIdentity {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func deduplicateAliasOutcomes(in []resolvedAliasTarget) []resolvedAliasTarget {
	if len(in) < 2 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].status != in[j].status {
			return in[i].status < in[j].status
		}
		return identityLess(in[i].identity, in[j].identity)
	})
	out := in[:1]
	for _, value := range in[1:] {
		last := out[len(out)-1]
		if value.status != last.status || value.identity != last.identity {
			out = append(out, value)
		}
	}
	return out
}
