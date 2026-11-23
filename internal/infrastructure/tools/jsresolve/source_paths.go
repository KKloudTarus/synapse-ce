package jsresolve

import (
	"context"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const maxSourcePathEntries = 64

type SourcePaths struct {
	mappings   []aliasMapping
	configs    []aliasConfigContext
	incomplete bool
}

type SourcePathResult struct {
	Target     string
	Applicable bool
	Uncertain  bool
}

func (p *SourcePaths) Observe(ctx context.Context, rel string, src []byte) error {
	if ctx == nil {
		return fmt.Errorf("%w: source paths observation requires a context", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(p.configs) >= maxSourcePathEntries {
		p.incomplete = true
		return nil
	}
	config := aliasConfigContext{source: rel, scopeDir: path.Dir(rel), uncertain: true}
	var mappings []aliasMapping
	if len(src) <= int(defaultMaxAliasFileBytes) && utf8.Valid(src) {
		limits := defaultAliasLimits()
		mappings, config, _ = parseTSConfigPaths(rel, src, limits)
	}
	if len(p.mappings)+len(mappings) > maxSourcePathEntries {
		config.uncertain = true
		mappings = nil
	}
	p.configs = append(p.configs, config)
	p.mappings = append(p.mappings, mappings...)
	return ctx.Err()
}

func (p *SourcePaths) Resolve(ctx context.Context, from, specifier string, modules map[string]bool) (SourcePathResult, error) {
	if ctx == nil {
		return SourcePathResult{}, fmt.Errorf("%w: source paths resolution requires a context", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return SourcePathResult{}, err
	}
	if strings.HasPrefix(specifier, ".") || strings.HasPrefix(specifier, "/") || jsresolution.ClassifySpecifier(specifier).Kind == jsresolution.SpecifierBuiltin {
		return SourcePathResult{}, nil
	}
	uncertain := SourcePathResult{Applicable: true, Uncertain: true}
	if p.incomplete {
		return uncertain, nil
	}
	budget := resolverWorkBudget{remaining: 2 * maxSourcePathEntries}
	matches, state := bestTSAliasMatches(ctx, p.mappings, p.configs, from, specifier, &budget)
	if err := ctx.Err(); err != nil {
		return SourcePathResult{}, err
	}
	if state != tsAliasContextNone || len(matches) > 1 {
		return uncertain, nil
	}
	if len(matches) == 0 {
		return SourcePathResult{}, nil
	}
	mapping := matches[0]
	capture, _ := aliasCapture(mapping.pattern, specifier)
	for _, target := range mapping.targets {
		if !budget.consume() {
			return uncertain, nil
		}
		target = substituteAliasTarget(target, capture)
		base := path.Clean(path.Join(mapping.baseDir, target))
		if strings.HasPrefix(target, "/") || hasDeclaredWindowsVolume(target) || base == ".." || strings.HasPrefix(base, "../") {
			return uncertain, nil
		}
		if path.Ext(base) == "" && mapping.moduleResolution != aliasModuleResolutionExtensionless {
			return uncertain, nil
		}
		for _, candidate := range tsAliasFileCandidates(base, mapping.moduleResolution) {
			if _, exists := modules[candidate]; exists {
				return SourcePathResult{Target: candidate, Applicable: true}, nil
			}
		}
	}
	return uncertain, nil
}
