package jsresolve

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func (r *Resolver) resolveTSPaths(
	ctx context.Context,
	base jsresolution.ImportResolution,
	mappings []aliasMapping,
	configs []aliasConfigContext,
	scopeDiscoveryComplete bool,
	workspaces map[string][]jsresolution.PackageIdentity,
	packages []jsresolution.PackageMetadata,
	modulePaths map[string]struct{},
	aliasWork *resolverWorkBudget,
	candidateWork *resolverWorkBudget,
	coverage *resolutionCoverageSink,
) (jsresolution.ImportResolution, bool) {
	if !scopeDiscoveryComplete {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "alias metadata discovery is incomplete, so a nearer tsconfig/jsconfig context may be unknown"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageUnsupportedAlias, Path: base.From,
			Detail: fmt.Sprintf("specifier %q cannot be classified safely because alias metadata discovery is incomplete", base.Specifier),
		})
		return base, true
	}
	matches, contextState := bestTSAliasMatches(ctx, mappings, configs, base.From, base.Specifier, aliasWork)
	switch contextState {
	case tsAliasContextBudget:
		return markAliasBudgetExceeded(base, aliasWork, coverage, r.limits.maxAliasWork), true
	case tsAliasContextUnsupported:
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{}
		base.Reason = "applicable tsconfig/jsconfig context uses unsupported project-selection or inheritance semantics"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageUnsupportedAlias, Path: base.From,
			Detail: fmt.Sprintf("specifier %q is under an alias context R2B cannot apply safely", base.Specifier),
		})
		return base, true
	case tsAliasContextAmbiguous:
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{}
		base.Reason = "multiple applicable tsconfig/jsconfig contexts make alias selection ambiguous"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageUnresolvedAlias, Path: base.From,
			Detail: fmt.Sprintf("specifier %q has multiple applicable tsconfig/jsconfig contexts", base.Specifier),
		})
		return base, true
	case tsAliasContextBaseURL:
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{}
		base.Reason = "tsconfig/jsconfig baseUrl may change bare-specifier identity and R2B does not reproduce TypeScript file resolution"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageUnsupportedAlias, Path: base.From,
			Detail: fmt.Sprintf("specifier %q is under a tsconfig/jsconfig baseUrl without a supported paths match", base.Specifier),
		})
		return base, true
	}
	if len(matches) == 0 {
		return base, false
	}
	return r.resolveAliasMatches(ctx, base, matches, workspaces, packages, modulePaths, aliasWork, candidateWork, coverage), true
}

func bestAliasMatchesInScope(ctx context.Context, mappings []aliasMapping, kind aliasKind, scopeDir, specifier string, budget *resolverWorkBudget) ([]aliasMapping, bool) {
	var scoped []aliasMapping
	for _, mapping := range mappings {
		if ctx.Err() != nil || !budget.consume() {
			return nil, true
		}
		if mapping.kind != kind || mapping.scopeDir != scopeDir {
			continue
		}
		if _, ok := aliasCapture(mapping.pattern, specifier); ok {
			scoped = append(scoped, mapping)
		}
	}
	return mostSpecificAliasMappings(scoped), false
}

type tsAliasContextState uint8

const (
	tsAliasContextNone tsAliasContextState = iota
	tsAliasContextBaseURL
	tsAliasContextAmbiguous
	tsAliasContextUnsupported
	tsAliasContextBudget
)

func bestTSAliasMatches(ctx context.Context, mappings []aliasMapping, configs []aliasConfigContext, importer, specifier string, budget *resolverWorkBudget) ([]aliasMapping, tsAliasContextState) {
	var applicable []aliasConfigContext
	for _, config := range configs {
		if ctx.Err() != nil || !budget.consume() {
			return nil, tsAliasContextBudget
		}
		if pathWithin(config.scopeDir, importer) {
			applicable = append(applicable, config)
		}
	}
	if len(applicable) == 0 {
		return nil, tsAliasContextNone
	}
	for _, config := range applicable {
		if config.uncertain {
			return nil, tsAliasContextUnsupported
		}
	}

	matchedBySource := make(map[string][]aliasMapping)
	for _, mapping := range mappings {
		if ctx.Err() != nil || !budget.consume() {
			return nil, tsAliasContextBudget
		}
		if mapping.kind != aliasTSConfigPaths || !pathWithin(mapping.scopeDir, importer) {
			continue
		}
		if _, ok := aliasCapture(mapping.pattern, specifier); ok {
			matchedBySource[mapping.source] = append(matchedBySource[mapping.source], mapping)
		}
	}

	if len(applicable) > 1 {
		for _, config := range applicable {
			if config.hasBaseURL {
				return nil, tsAliasContextAmbiguous
			}
		}
		if len(matchedBySource) > 0 {
			return nil, tsAliasContextAmbiguous
		}
	}
	if len(applicable) == 1 {
		config := applicable[0]
		if matches := matchedBySource[config.source]; len(matches) > 0 {
			return mostSpecificAliasMappings(matches), tsAliasContextNone
		}
		if config.hasBaseURL {
			return nil, tsAliasContextBaseURL
		}
	}
	return nil, tsAliasContextNone
}

func mostSpecificAliasMappings(scoped []aliasMapping) []aliasMapping {
	if len(scoped) < 2 {
		return scoped
	}
	if scoped[0].kind == aliasTSConfigPaths {
		bestPrefix := -1
		var out []aliasMapping
		for _, mapping := range scoped {
			prefix, _ := aliasSpecificity(mapping.pattern)
			if prefix > bestPrefix {
				bestPrefix = prefix
				out = out[:0]
			}
			if prefix == bestPrefix {
				out = append(out, mapping)
			}
		}
		sort.Slice(out, func(i, j int) bool { return aliasMappingLess(out[i], out[j]) })
		return out
	}

	// Node package-import pattern precedence compares the prefix before '*' first
	// and then the total pattern length (equivalent here to suffix length once
	// the prefix is tied). Exact keys rank above patterns.
	bestPrefix, bestSuffix := -1, -1
	var out []aliasMapping
	for _, mapping := range scoped {
		prefix, suffix := aliasSpecificity(mapping.pattern)
		if prefix > bestPrefix || (prefix == bestPrefix && suffix > bestSuffix) {
			bestPrefix, bestSuffix = prefix, suffix
			out = out[:0]
		}
		if prefix == bestPrefix && suffix == bestSuffix {
			out = append(out, mapping)
		}
	}
	sort.Slice(out, func(i, j int) bool { return aliasMappingLess(out[i], out[j]) })
	return out
}

func aliasSpecificity(pattern string) (int, int) {
	star := strings.IndexByte(pattern, '*')
	if star < 0 {
		return len(pattern) + 1, len(pattern) + 1
	}
	return star, len(pattern) - star - 1
}

func aliasCapture(pattern, specifier string) (string, bool) {
	star := strings.IndexByte(pattern, '*')
	if star < 0 {
		return "", pattern == specifier
	}
	prefix, suffix := pattern[:star], pattern[star+1:]
	if !strings.HasPrefix(specifier, prefix) || !strings.HasSuffix(specifier, suffix) || len(specifier) < len(prefix)+len(suffix) {
		return "", false
	}
	return specifier[len(prefix) : len(specifier)-len(suffix)], true
}

func substituteAliasTarget(target, capture string) string {
	if star := strings.IndexByte(target, '*'); star >= 0 {
		return target[:star] + capture + target[star+1:]
	}
	return target
}

func observedTSAliasTarget(target string, modules map[string]struct{}, mode aliasModuleResolution) bool {
	if len(modules) == 0 {
		return false
	}
	if _, ok := modules[target]; ok {
		return true
	}

	// Extension substitution is valid across TypeScript module-resolution modes
	// when the paths target names a JavaScript-family file explicitly. The rewrite
	// table lives in the domain so the source scanner (phase R1) and this resolver
	// cannot disagree about which file a specifier names.
	if ext := path.Ext(target); ext != "" {
		base := strings.TrimSuffix(target, ext)
		for _, rewrite := range jsresolution.EmittedExtensionCandidates(ext) {
			if _, ok := modules[base+rewrite]; ok {
				return true
			}
		}
	}
	if mode != aliasModuleResolutionExtensionless {
		return false
	}
	if path.Ext(target) != "" {
		return false
	}
	for _, ext := range jsresolution.ModuleSourceExtensions() {
		if _, ok := modules[target+ext]; ok {
			return true
		}
		if _, ok := modules[path.Join(target, "index"+ext)]; ok {
			return true
		}
	}
	return false
}
