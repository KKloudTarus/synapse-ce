package jsresolve

import (
	"context"
	"errors"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

func (b *aliasInventoryBuilder) Build(ctx context.Context, root string) (aliasInventory, error) {
	if ctx == nil {
		return aliasInventory{}, fmt.Errorf("%w: context is required", shared.ErrValidation)
	}
	if b == nil {
		return aliasInventory{}, fmt.Errorf("%w: alias inventory builder is required", shared.ErrValidation)
	}
	if err := b.limits.validate(); err != nil {
		return aliasInventory{}, err
	}
	if strings.TrimSpace(root) == "" {
		return aliasInventory{}, fmt.Errorf("%w: repository root is required", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return aliasInventory{}, err
	}
	rootAbs, err := filepathAbsClean(root)
	if err != nil {
		return aliasInventory{}, fmt.Errorf("%w: resolve repository root: %v", shared.ErrValidation, err)
	}
	rootInfo, err := os.Lstat(rootAbs)
	if err != nil {
		return aliasInventory{}, fmt.Errorf("%w: repository root: %v", shared.ErrValidation, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return aliasInventory{}, fmt.Errorf("%w: repository root must be a real directory", shared.ErrValidation)
	}
	rootDir, err := os.OpenRoot(rootAbs)
	if err != nil {
		return aliasInventory{}, fmt.Errorf("%w: open repository root: %v", shared.ErrValidation, err)
	}
	defer func() { _ = rootDir.Close() }()

	var mappings []aliasMapping
	var configs []aliasConfigContext
	var packageScopes []aliasPackageContext
	coverage := aliasCoverageSink{limit: b.limits.maxCoverageIssues}
	entries, files := 0, 0
	bytesRead := int64(0)
	scopeDiscoveryComplete := true
	mappingBudgetExhausted := false
	walkErr := fs.WalkDir(rootDir.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			if rel == "." {
				return fmt.Errorf("walk repository root: %w", walkErr)
			}
			scopeDiscoveryComplete = false
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "alias metadata entry could not be inspected"})
			return nil
		}
		entries++
		if entries > b.limits.maxEntries {
			scopeDiscoveryComplete = false
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: ".", Detail: fmt.Sprintf("alias filesystem entry budget exceeded (%d)", b.limits.maxEntries)})
			return fs.SkipAll
		}
		if entry.IsDir() {
			if rel != "." && skipMetadataDir(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !isAliasMetadataFile(entry.Name()) {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.Name() == "package.json" {
				packageScopes = append(packageScopes, aliasPackageContext{source: rel, scopeDir: path.Dir(rel), uncertain: true})
			}
			if entry.Name() == "tsconfig.json" || entry.Name() == "jsconfig.json" {
				configs = append(configs, aliasConfigContext{source: rel, scopeDir: path.Dir(rel), uncertain: true})
			}
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "alias metadata is symlinked and was not followed"})
			return nil
		}
		if files >= b.limits.maxFiles {
			scopeDiscoveryComplete = false
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: rel, Detail: fmt.Sprintf("alias metadata file budget exceeded (%d)", b.limits.maxFiles)})
			return fs.SkipAll
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() {
			if entry.Name() == "package.json" {
				packageScopes = append(packageScopes, aliasPackageContext{source: rel, scopeDir: path.Dir(rel), uncertain: true})
			}
			if entry.Name() == "tsconfig.json" || entry.Name() == "jsconfig.json" {
				configs = append(configs, aliasConfigContext{source: rel, scopeDir: path.Dir(rel), uncertain: true})
			}
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "alias metadata entry is not a stable regular file"})
			return nil
		}
		remaining := b.limits.maxTotalBytes - bytesRead
		if remaining <= 0 || info.Size() > remaining {
			scopeDiscoveryComplete = false
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: rel, Detail: fmt.Sprintf("aggregate alias metadata byte budget exceeded (%d)", b.limits.maxTotalBytes)})
			return fs.SkipAll
		}
		files++
		content, readErr := readBoundedMetadata(rootDir, rel, info, b.limits.maxFileBytes, remaining)
		if readErr != nil {
			if entry.Name() == "package.json" {
				packageScopes = append(packageScopes, aliasPackageContext{source: rel, scopeDir: path.Dir(rel), uncertain: true})
			}
			if entry.Name() == "tsconfig.json" || entry.Name() == "jsconfig.json" {
				configs = append(configs, aliasConfigContext{source: rel, scopeDir: path.Dir(rel), uncertain: true})
			}
			kind := jsresolution.CoverageUnreadableMetadata
			if errorsIsMetadataBudget(readErr) {
				kind = jsresolution.CoverageMetadataBudgetExceeded
			}
			coverage.add(jsresolution.CoverageIssue{Kind: kind, Path: rel, Detail: readErr.Error()})
			if errors.Is(readErr, errMetadataTotalBudget) {
				scopeDiscoveryComplete = false
				return fs.SkipAll
			}
			return nil
		}
		bytesRead += int64(len(content))

		var parsed []aliasMapping
		var issues []jsresolution.CoverageIssue
		var packageContext aliasPackageContext
		var config aliasConfigContext
		isPackage := entry.Name() == "package.json"
		isConfig := entry.Name() == "tsconfig.json" || entry.Name() == "jsconfig.json"
		switch entry.Name() {
		case "package.json":
			parsed, packageContext, issues = parsePackageImports(rel, content, b.limits)
		case "tsconfig.json", "jsconfig.json":
			parsed, config, issues = parseTSConfigPaths(rel, content, b.limits)
		}
		coverage.addAll(issues)

		remainingMappings := b.limits.maxMappings - len(mappings)
		if mappingBudgetExhausted || len(parsed) > remainingMappings {
			if len(parsed) > 0 {
				if !mappingBudgetExhausted {
					coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: rel, Detail: fmt.Sprintf("alias mapping budget exceeded (%d)", b.limits.maxMappings)})
				}
				mappingBudgetExhausted = true
				if isPackage {
					packageContext.uncertain = true
				}
				if isConfig {
					config.uncertain = true
				}
				parsed = nil
			}
		}
		if isPackage {
			packageScopes = append(packageScopes, packageContext)
		}
		if isConfig {
			configs = append(configs, config)
		}
		mappings = append(mappings, parsed...)
		return nil
	})
	if walkErr != nil {
		if err := ctx.Err(); err != nil {
			return aliasInventory{}, err
		}
		return aliasInventory{}, fmt.Errorf("inventory javascript alias metadata: %w", walkErr)
	}

	sort.Slice(mappings, func(i, j int) bool { return aliasMappingLess(mappings[i], mappings[j]) })
	mappings = deduplicateAliasMappings(mappings)
	sort.Slice(configs, func(i, j int) bool {
		if configs[i].scopeDir != configs[j].scopeDir {
			return configs[i].scopeDir < configs[j].scopeDir
		}
		return configs[i].source < configs[j].source
	})
	configs = deduplicateAliasConfigs(configs)
	sort.Slice(packageScopes, func(i, j int) bool {
		if packageScopes[i].scopeDir != packageScopes[j].scopeDir {
			return packageScopes[i].scopeDir < packageScopes[j].scopeDir
		}
		return packageScopes[i].source < packageScopes[j].source
	})
	packageScopes = deduplicateAliasPackageContexts(packageScopes)
	out := aliasInventory{
		mappings: mappings, configs: configs, packageScopes: packageScopes,
		coverage: coverage.issues, scopeDiscoveryComplete: scopeDiscoveryComplete,
	}
	sort.Slice(out.coverage, func(i, j int) bool {
		a, c := out.coverage[i], out.coverage[j]
		if a.Kind != c.Kind {
			return a.Kind < c.Kind
		}
		if a.Path != c.Path {
			return a.Path < c.Path
		}
		return a.Detail < c.Detail
	})
	out.coverage = deduplicateAliasCoverage(out.coverage)
	return out, nil
}

func errorsIsMetadataBudget(err error) bool {
	return errors.Is(err, errMetadataTooLarge) || errors.Is(err, errMetadataTotalBudget)
}

func isAliasMetadataFile(name string) bool {
	return name == "package.json" || name == "tsconfig.json" || name == "jsconfig.json"
}
