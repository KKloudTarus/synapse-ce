package jsresolve

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

type resolvedAliasTarget struct {
	status   jsresolution.Status
	identity jsresolution.PackageIdentity
	reason   string
}

func (r *Resolver) resolveAliasMatches(
	ctx context.Context,
	base jsresolution.ImportResolution,
	matches []aliasMapping,
	workspaces map[string][]jsresolution.PackageIdentity,
	packages []jsresolution.PackageMetadata,
	components *componentIndex,
	modulePaths map[string]struct{},
	aliasWork *resolverWorkBudget,
	candidateWork *resolverWorkBudget,
	coverage *resolutionCoverageSink,
) jsresolution.ImportResolution {
	var outcomes []resolvedAliasTarget
	for _, mapping := range matches {
		capture, ok := aliasCapture(mapping.pattern, base.Specifier)
		if !ok {
			continue
		}
		for _, target := range mapping.targets {
			if !aliasWork.consume() {
				return markAliasBudgetExceeded(base, aliasWork, coverage, r.limits.maxAliasWork)
			}
			if err := ctx.Err(); err != nil {
				base.Status = jsresolution.StatusUnresolved
				base.Reason = err.Error()
				return base
			}
			expanded := substituteAliasTarget(target, capture)
			resolved, failure := resolveAliasTargets(mapping, expanded, workspaces, packages, components, modulePaths, r.limits.maxCandidates)
			if len(resolved) > 0 {
				if !candidateWork.consumeN(len(resolved)) {
					return markCandidateBudgetExceeded(base, candidateWork, coverage, r.limits.maxCandidateWork)
				}
				outcomes = append(outcomes, resolved...)
				if len(outcomes) > r.limits.maxCandidates {
					base.Status = jsresolution.StatusUnresolved
					base.Package = jsresolution.PackageIdentity{}
					base.Candidates = nil
					base.Reason = "alias identity candidate budget exceeded"
					coverage.add(jsresolution.CoverageIssue{
						Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: base.From,
						Detail: fmt.Sprintf("alias candidate budget exceeded for %q (%d)", base.Specifier, r.limits.maxCandidates),
					})
					return base
				}
				// TypeScript paths arrays are ordered fallbacks. Once one target
				// resolves, later entries are not viable candidates.
				if mapping.kind == aliasTSConfigPaths {
					break
				}
			}
			if failure != "" && !(mapping.kind == aliasTSConfigPaths && failure == jsresolution.CoverageUnresolvedAlias) {
				coverage.add(jsresolution.CoverageIssue{
					Kind: failure, Path: base.From,
					Detail: fmt.Sprintf("alias %q target %q cannot be resolved safely", base.Specifier, expanded),
				})
			}
		}
	}
	outcomes = deduplicateAliasOutcomes(outcomes)
	if len(outcomes) == 0 {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "alias targets do not map to a supported package identity"
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnresolvedAlias, Path: base.From, Detail: fmt.Sprintf("alias %q has no deterministic package identity", base.Specifier)})
		return base
	}
	if len(outcomes) == 1 {
		base.Status = outcomes[0].status
		base.Package = outcomes[0].identity
		base.Reason = outcomes[0].reason
		return base
	}

	base.Status = jsresolution.StatusAmbiguous
	base.Package = jsresolution.PackageIdentity{}
	base.Candidates = make([]jsresolution.PackageIdentity, 0, len(outcomes))
	for _, outcome := range outcomes {
		base.Candidates = append(base.Candidates, outcome.identity)
	}
	sort.Slice(base.Candidates, func(i, j int) bool { return identityLess(base.Candidates[i], base.Candidates[j]) })
	base.Candidates = deduplicatePackageIdentities(base.Candidates)
	base.Reason = "alias maps to multiple viable package identities"
	coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnresolvedAlias, Path: base.From, Detail: fmt.Sprintf("alias %q maps to multiple viable package identities", base.Specifier)})
	return base
}

func resolveAliasTargets(
	mapping aliasMapping,
	target string,
	workspaces map[string][]jsresolution.PackageIdentity,
	packages []jsresolution.PackageMetadata,
	components *componentIndex,
	modulePaths map[string]struct{},
	maxCandidates int,
) ([]resolvedAliasTarget, jsresolution.CoverageIssueKind) {
	if mapping.kind == aliasPackageImports && !strings.HasPrefix(target, "./") {
		classified := jsresolution.ClassifySpecifier(target)
		switch classified.Kind {
		case jsresolution.SpecifierBuiltin:
			return []resolvedAliasTarget{{status: jsresolution.StatusBuiltin, identity: jsresolution.PackageIdentity{Name: classified.BuiltinName}, reason: "resolved through package.json imports"}}, ""
		case jsresolution.SpecifierPackage:
			local := workspaces[classified.PackageName]
			registry, _ := components.lookup(classified.PackageName)
			if len(local) == 0 {
				// An imports target naming a third-party package is correlated exactly like a bare
				// import: one component version is a deterministic identity, several stay ambiguous,
				// and none degrades coverage rather than silently disappearing.
				switch len(registry) {
				case 0:
					return []resolvedAliasTarget{{
						status:   jsresolution.StatusUnresolved,
						identity: jsresolution.PackageIdentity{Name: classified.PackageName},
						reason:   "package.json imports target names an npm package with no matching sbom component",
					}}, jsresolution.CoverageMissingSBOMComponent
				case 1:
					return []resolvedAliasTarget{{
						status:   jsresolution.StatusComponent,
						identity: registry[0],
						reason:   "package.json imports target correlated to an sbom component",
					}}, ""
				default:
					if len(registry) >= maxCandidates {
						return nil, jsresolution.CoverageMetadataBudgetExceeded
					}
					out := make([]resolvedAliasTarget, 0, len(registry))
					for _, candidate := range registry {
						out = append(out, resolvedAliasTarget{
							status:   jsresolution.StatusUnresolved,
							identity: candidate,
							reason:   "package.json imports target matches multiple sbom component versions",
						})
					}
					return out, jsresolution.CoverageAmbiguousSBOMComponent
				}
			}
			// A package.json imports target names a package, not a concrete workspace path. Without
			// importer/lockfile selection, a same-name registry package remains viable just as it does
			// for a bare import.
			if len(local)+len(registry) >= maxCandidates {
				return nil, jsresolution.CoverageMetadataBudgetExceeded
			}
			out := make([]resolvedAliasTarget, 0, len(local)+len(registry)+1)
			for _, candidate := range local {
				out = append(out, resolvedAliasTarget{status: jsresolution.StatusWorkspace, identity: candidate, reason: "package.json imports target matches a local workspace"})
			}
			for _, candidate := range registry {
				out = append(out, resolvedAliasTarget{
					status:   jsresolution.StatusUnresolved,
					identity: candidate,
					reason:   "package.json imports target may resolve to this registry component; importer context is required to select one",
				})
			}
			if len(registry) == 0 {
				out = append(out, resolvedAliasTarget{
					status:   jsresolution.StatusUnresolved,
					identity: jsresolution.PackageIdentity{Name: classified.PackageName},
					reason:   "package.json imports target may resolve to a registry package; importer context is required to select one",
				})
			}
			return out, ""
		default:
			return nil, jsresolution.CoverageUnsupportedAlias
		}
	}

	base := mapping.baseDir
	joined := path.Clean(path.Join(base, target))
	if strings.HasPrefix(target, "/") || hasDeclaredWindowsVolume(target) || joined == ".." || strings.HasPrefix(joined, "../") {
		return nil, jsresolution.CoverageWorkspaceRootEscape
	}
	joined = strings.TrimPrefix(joined, "./")
	if joined == "" {
		joined = "."
	}
	if mapping.kind == aliasPackageImports {
		// Node package-import targets beginning with ./ are confined to the
		// declaring package and cannot traverse into node_modules.
		if !pathWithin(mapping.scopeDir, joined) {
			return nil, jsresolution.CoverageWorkspaceRootEscape
		}
		if containsPathSegment(joined, "node_modules") {
			return nil, jsresolution.CoverageUnsupportedAlias
		}
	}
	pkg, ok := packageForRepositoryTarget(packages, joined)
	if !ok {
		return nil, jsresolution.CoverageUnresolvedAlias
	}
	if mapping.kind == aliasTSConfigPaths && !observedTSAliasTarget(joined, modulePaths, mapping.moduleResolution) {
		// TypeScript paths entries are substitutions followed by file resolution.
		// If the substituted first-party target is not observable in the source
		// graph, TypeScript may fall back to the original bare package specifier.
		// Refuse to call it local without positive source evidence.
		return nil, jsresolution.CoverageUnresolvedAlias
	}
	identity := packageMetadataIdentity(pkg)
	if pkg.Workspace {
		if pkg.Name == "" {
			return nil, jsresolution.CoverageUnresolvedAlias
		}
		return []resolvedAliasTarget{{status: jsresolution.StatusWorkspace, identity: identity, reason: aliasResolutionReason(mapping.kind)}}, ""
	}
	return []resolvedAliasTarget{{status: jsresolution.StatusLocal, identity: identity, reason: aliasResolutionReason(mapping.kind)}}, ""
}

func aliasResolutionReason(kind aliasKind) string {
	if kind == aliasPackageImports {
		return "resolved through package.json imports"
	}
	return "resolved through tsconfig/jsconfig paths"
}
