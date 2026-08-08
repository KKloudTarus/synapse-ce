package jsresolve

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func indexWorkspacesByName(packages []jsresolution.PackageMetadata) map[string][]jsresolution.PackageIdentity {
	out := make(map[string][]jsresolution.PackageIdentity)
	for _, pkg := range packages {
		if !pkg.Workspace || pkg.Name == "" {
			continue
		}
		identity := packageMetadataIdentity(pkg)
		out[pkg.Name] = append(out[pkg.Name], identity)
	}
	for name := range out {
		sort.Slice(out[name], func(i, j int) bool { return identityLess(out[name][i], out[name][j]) })
		out[name] = deduplicatePackageIdentities(out[name])
	}
	return out
}

func (r *Resolver) resolvePackageRoot(
	base jsresolution.ImportResolution,
	packageName string,
	workspaces map[string][]jsresolution.PackageIdentity,
	candidateWork *resolverWorkBudget,
	coverage *resolutionCoverageSink,
) jsresolution.ImportResolution {
	local := workspaces[packageName]
	if len(local) == 0 {
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{Name: packageName}
		base.Reason = "npm package root classified; SBOM component correlation deferred to R2C"
		return base
	}

	// A workspace declaration proves that a local package with this name exists,
	// but it does not prove that a particular importer resolves to that workspace.
	// npm-family managers may install a registry package of the same name when an
	// importer's requested range or lockfile context does not select the local
	// workspace. R2C owns that importer/lockfile disambiguation. Until then,
	// preserve both identities rather than turning workspace discovery into false
	// package identity confidence.
	if len(local) >= r.limits.maxCandidates {
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{Name: packageName}
		base.Reason = "workspace plus external package identity candidate budget exceeded"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: base.From,
			Detail: fmt.Sprintf("workspace/importer candidate budget exceeded for %q (%d)", packageName, r.limits.maxCandidates),
		})
		return base
	}
	if !candidateWork.consumeN(len(local) + 1) {
		return markCandidateBudgetExceeded(base, candidateWork, coverage, r.limits.maxCandidateWork)
	}

	candidates := make([]jsresolution.PackageIdentity, 0, len(local)+1)
	candidates = append(candidates, local...)
	candidates = append(candidates, jsresolution.PackageIdentity{Name: packageName})
	sort.Slice(candidates, func(i, j int) bool { return identityLess(candidates[i], candidates[j]) })
	candidates = deduplicatePackageIdentities(candidates)

	base.Status = jsresolution.StatusAmbiguous
	base.Candidates = candidates
	base.Reason = "package name matches a local workspace, but importer and lockfile context are required to distinguish workspace linking from a registry package"
	coverage.add(jsresolution.CoverageIssue{
		Kind: jsresolution.CoverageUnresolvedSpecifier, Path: base.From,
		Detail: fmt.Sprintf("specifier %q matches local workspace %q but importer/lockfile selection is deferred to R2C", base.Specifier, packageName),
	})
	return base
}

func (r *Resolver) resolvePackageImport(
	ctx context.Context,
	base jsresolution.ImportResolution,
	mappings []aliasMapping,
	packageScopes []aliasPackageContext,
	scopeDiscoveryComplete bool,
	workspaces map[string][]jsresolution.PackageIdentity,
	packages []jsresolution.PackageMetadata,
	aliasWork *resolverWorkBudget,
	candidateWork *resolverWorkBudget,
	coverage *resolutionCoverageSink,
) jsresolution.ImportResolution {
	if !scopeDiscoveryComplete {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "package scope discovery is incomplete, so a nearer package boundary may be unknown"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageUnsupportedAlias, Path: base.From,
			Detail: fmt.Sprintf("package import %q cannot be scoped safely because alias metadata discovery is incomplete", base.Specifier),
		})
		return base
	}
	scope, ok := packageContextForImporter(packageScopes, base.From)
	if !ok {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "importer is not contained by an observed package.json boundary"
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnresolvedAlias, Path: base.From, Detail: fmt.Sprintf("package import %q has no containing package scope", base.Specifier)})
		return base
	}
	if scope.uncertain {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "nearest package.json boundary has incomplete or unsupported imports metadata"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageUnsupportedAlias, Path: base.From,
			Detail: fmt.Sprintf("package import %q cannot be resolved safely in package scope %q", base.Specifier, scope.scopeDir),
		})
		return base
	}
	if !scope.importsPresent {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "nearest package scope does not declare package.json imports"
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnresolvedAlias, Path: base.From, Detail: fmt.Sprintf("package import %q is not declared in package scope %q", base.Specifier, scope.scopeDir)})
		return base
	}
	matches, exhausted := bestAliasMatchesInScope(ctx, mappings, aliasPackageImports, scope.scopeDir, base.Specifier, aliasWork)
	if exhausted {
		return markAliasBudgetExceeded(base, aliasWork, coverage, r.limits.maxAliasWork)
	}
	if len(matches) == 0 {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "no supported package.json imports mapping exists in the nearest package scope"
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnresolvedAlias, Path: base.From, Detail: fmt.Sprintf("package import %q could not be resolved in package scope %q", base.Specifier, scope.scopeDir)})
		return base
	}
	return r.resolveAliasMatches(ctx, base, matches, workspaces, packages, nil, aliasWork, candidateWork, coverage)
}
