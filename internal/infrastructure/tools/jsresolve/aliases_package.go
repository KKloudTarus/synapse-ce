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

func parsePackageImports(rel string, content []byte, limits aliasLimits) ([]aliasMapping, aliasPackageContext, []jsresolution.CoverageIssue) {
	context := aliasPackageContext{source: rel, scopeDir: path.Dir(rel)}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(content, &doc); err != nil {
		context.uncertain = true
		return nil, context, []jsresolution.CoverageIssue{{Kind: jsresolution.CoverageMalformedMetadata, Path: rel, Detail: "package.json alias metadata is malformed JSON"}}
	}
	raw, ok := doc["imports"]
	if !ok {
		return nil, context, nil
	}
	context.importsPresent = true
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		context.uncertain = true
		return nil, context, []jsresolution.CoverageIssue{{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: "package.json imports must be an object for source-only resolution"}}
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		context.uncertain = true
		return nil, context, []jsresolution.CoverageIssue{{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: "package.json imports must be an object for source-only resolution"}}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	mappings := make([]aliasMapping, 0, len(keys))
	var issues []jsresolution.CoverageIssue
	for _, key := range keys {
		if len(key) > limits.maxPatternBytes || !validPackageImportPattern(key) {
			context.uncertain = true
			issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: fmt.Sprintf("unsupported package imports key %q", key)})
			continue
		}
		var target string
		if err := json.Unmarshal(values[key], &target); err != nil {
			context.uncertain = true
			issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: fmt.Sprintf("package imports key %q uses conditional or fallback targets", key)})
			continue
		}
		if len(target) > limits.maxPatternBytes || !validPackageImportTarget(key, target) {
			context.uncertain = true
			issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: fmt.Sprintf("unsupported package imports target for %q", key)})
			continue
		}
		if strings.HasPrefix(target, "./") {
			cleaned := path.Clean(target)
			if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
				context.uncertain = true
				issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageWorkspaceRootEscape, Path: rel, Detail: fmt.Sprintf("package imports target for %q escapes its package scope", key)})
				continue
			}
			if containsPathSegment(cleaned, "node_modules") {
				context.uncertain = true
				issues = append(issues, jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedAlias, Path: rel, Detail: fmt.Sprintf("package imports target for %q traverses node_modules", key)})
				continue
			}
		}
		mappings = append(mappings, aliasMapping{
			kind: aliasPackageImports, source: rel, scopeDir: path.Dir(rel), baseDir: path.Dir(rel), pattern: key, targets: []string{target},
		})
	}
	return mappings, context, issues
}

func validPackageImportPattern(pattern string) bool {
	return strings.HasPrefix(pattern, "#") && pattern != "#" && !strings.HasPrefix(pattern, "#/") &&
		strings.IndexByte(pattern, 0) < 0 && !strings.ContainsAny(pattern, "\r\n\t ") && strings.Count(pattern, "*") <= 1
}

func validPackageImportTarget(pattern, target string) bool {
	if target == "" || strings.IndexByte(target, 0) >= 0 || strings.ContainsAny(target, "\r\n\t") || strings.Count(target, "*") > 1 {
		return false
	}
	if strings.Count(pattern, "*") == 0 && strings.Contains(target, "*") {
		return false
	}
	if strings.HasPrefix(target, "./") {
		return true
	}
	kind := jsresolution.ClassifySpecifier(target).Kind
	return kind == jsresolution.SpecifierBuiltin || kind == jsresolution.SpecifierPackage
}
