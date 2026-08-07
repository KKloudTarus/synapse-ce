package jsresolve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"path"
	"sort"
	"strings"
)

func parseTSConfigPaths(rel string, content []byte, limits aliasLimits) ([]aliasMapping, aliasConfigContext, []jsresolution.CoverageIssue) {
	config := aliasConfigContext{source: rel, scopeDir: path.Dir(rel)}
	cleaned, err := sanitizeJSONC(content)
	if err != nil {
		config.uncertain = true
		return nil, config, []jsresolution.CoverageIssue{{Kind: jsresolution.CoverageMalformedMetadata, Path: rel, Detail: err.Error()}}
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(cleaned, &doc); err != nil {
		config.uncertain = true
		return nil, config, []jsresolution.CoverageIssue{{Kind: jsresolution.CoverageMalformedMetadata, Path: rel, Detail: "tsconfig/jsconfig alias metadata is malformed JSONC"}}
	}
	var issues []jsresolution.CoverageIssue
	if rawExtends, ok := doc["extends"]; ok && !bytes.Equal(bytes.TrimSpace(rawExtends), []byte("null")) {
		config.uncertain = true
		issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: "tsconfig/jsconfig inheritance via extends is not resolved in R2B"})
	}
	selectionPresent := false
	for _, key := range []string{"files", "include", "exclude"} {
		if raw, ok := doc[key]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			selectionPresent = true
		}
	}

	rawCompiler, ok := doc["compilerOptions"]
	if !ok {
		return nil, config, issues
	}
	var compiler map[string]json.RawMessage
	if err := json.Unmarshal(rawCompiler, &compiler); err != nil || compiler == nil {
		config.uncertain = true
		issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: rel, Detail: "compilerOptions must be an object"})
		return nil, config, issues
	}

	moduleResolution := aliasModuleResolutionUnknown
	if rawMode, ok := compiler["moduleResolution"]; ok {
		var mode string
		if err := json.Unmarshal(rawMode, &mode); err != nil {
			config.uncertain = true
			issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: "compilerOptions.moduleResolution must be a supported string for source-only paths resolution"})
		} else {
			switch strings.ToLower(strings.TrimSpace(mode)) {
			case "bundler", "node", "node10", "classic":
				moduleResolution = aliasModuleResolutionExtensionless
			case "node16", "nodenext":
				moduleResolution = aliasModuleResolutionStrictNode
			default:
				config.uncertain = true
				issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: fmt.Sprintf("unsupported compilerOptions.moduleResolution %q", mode)})
			}
		}
	}

	_, hasPaths := compiler["paths"]
	_, hasBaseURL := compiler["baseUrl"]
	if selectionPresent && (hasPaths || hasBaseURL) {
		config.uncertain = true
		issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: "tsconfig/jsconfig project files/include/exclude membership is not resolved in R2B"})
	}
	configDir := path.Dir(rel)
	baseDir := configDir
	if rawBase, ok := compiler["baseUrl"]; ok {
		config.hasBaseURL = true
		var base string
		if err := json.Unmarshal(rawBase, &base); err != nil || base == "" {
			config.uncertain = true
			issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: rel, Detail: "compilerOptions.baseUrl must be a non-empty string"})
			return nil, config, issues
		}
		base = strings.ReplaceAll(base, "\\", "/")
		joined := path.Clean(path.Join(configDir, base))
		if joined == ".." || strings.HasPrefix(joined, "../") || strings.HasPrefix(base, "/") || hasDeclaredWindowsVolume(base) {
			config.uncertain = true
			issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageWorkspaceRootEscape, Path: rel, Detail: "tsconfig/jsconfig baseUrl escapes repository root"})
			return nil, config, issues
		}
		baseDir = strings.TrimPrefix(joined, "./")
		if baseDir == "" {
			baseDir = "."
		}
	}

	rawPaths, ok := compiler["paths"]
	if !ok {
		return nil, config, issues
	}
	var paths map[string]json.RawMessage
	if err := json.Unmarshal(rawPaths, &paths); err != nil || paths == nil {
		config.uncertain = true
		issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: rel, Detail: "compilerOptions.paths must be an object"})
		return nil, config, issues
	}

	keys := make([]string, 0, len(paths))
	for key := range paths {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	mappings := make([]aliasMapping, 0, len(keys))
	for _, key := range keys {
		if len(key) > limits.maxPatternBytes || !validTSPathPattern(key) {
			config.uncertain = true
			issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: fmt.Sprintf("unsupported tsconfig/jsconfig paths key %q", key)})
			continue
		}
		var targets []string
		if err := json.Unmarshal(paths[key], &targets); err != nil || len(targets) == 0 {
			config.uncertain = true
			issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: fmt.Sprintf("paths key %q must map to a non-empty string array", key)})
			continue
		}
		if len(targets) > limits.maxTargets {
			config.uncertain = true
			issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: rel, Detail: fmt.Sprintf("paths target budget exceeded for %q (%d)", key, limits.maxTargets)})
			targets = targets[:limits.maxTargets]
		}
		validTargets := make([]string, 0, len(targets))
		for _, target := range targets {
			target = strings.ReplaceAll(target, "\\", "/")
			if len(target) > limits.maxPatternBytes || !validTSPathTarget(key, target) {
				config.uncertain = true
				issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: fmt.Sprintf("unsupported paths target for %q", key)})
				continue
			}
			if containsPathSegment(target, "node_modules") || strings.Contains(target, ":") {
				config.uncertain = true
				issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: fmt.Sprintf("paths target for %q uses an unsupported package/URL-like location", key)})
				continue
			}
			joined := path.Clean(path.Join(baseDir, target))
			if strings.HasPrefix(target, "/") || hasDeclaredWindowsVolume(target) || joined == ".." || strings.HasPrefix(joined, "../") {
				config.uncertain = true
				issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageWorkspaceRootEscape, Path: rel, Detail: fmt.Sprintf("paths target for %q escapes repository root", key)})
				continue
			}
			validTargets = append(validTargets, target)
		}
		if len(validTargets) == 0 {
			continue
		}
		mappings = append(mappings, aliasMapping{
			kind: aliasTSConfigPaths, source: rel, scopeDir: configDir, baseDir: baseDir,
			pattern: key, targets: validTargets, moduleResolution: moduleResolution,
		})
	}
	return mappings, config, issues
}

func validTSPathPattern(pattern string) bool {
	return pattern != "" && strings.IndexByte(pattern, 0) < 0 && !strings.ContainsAny(pattern, "\r\n\t") && strings.Count(pattern, "*") <= 1
}

func validTSPathTarget(pattern, target string) bool {
	if target == "" || strings.IndexByte(target, 0) >= 0 || strings.ContainsAny(target, "\r\n\t") || strings.Count(target, "*") > 1 {
		return false
	}
	return strings.Count(pattern, "*") != 0 || !strings.Contains(target, "*")
}

func hasDeclaredWindowsVolume(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) && value[1] == ':'
}
