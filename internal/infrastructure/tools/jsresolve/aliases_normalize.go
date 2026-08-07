package jsresolve

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func aliasMappingLess(a, b aliasMapping) bool {
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	if a.scopeDir != b.scopeDir {
		return a.scopeDir < b.scopeDir
	}
	if a.source != b.source {
		return a.source < b.source
	}
	if a.pattern != b.pattern {
		return a.pattern < b.pattern
	}
	if a.baseDir != b.baseDir {
		return a.baseDir < b.baseDir
	}
	if a.moduleResolution != b.moduleResolution {
		return a.moduleResolution < b.moduleResolution
	}
	return stringSliceLess(a.targets, b.targets)
}

func stringSliceLess(a, b []string) bool {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func deduplicateAliasMappings(in []aliasMapping) []aliasMapping {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		last := out[len(out)-1]
		if value.kind != last.kind || value.source != last.source || value.scopeDir != last.scopeDir || value.baseDir != last.baseDir ||
			value.pattern != last.pattern || value.moduleResolution != last.moduleResolution || !equalStrings(value.targets, last.targets) {
			out = append(out, value)
		}
	}
	return out
}

func deduplicateAliasConfigs(in []aliasConfigContext) []aliasConfigContext {
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

func deduplicateAliasPackageContexts(in []aliasPackageContext) []aliasPackageContext {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		last := &out[len(out)-1]
		if value.source == last.source && value.scopeDir == last.scopeDir {
			last.importsPresent = last.importsPresent || value.importsPresent
			last.uncertain = last.uncertain || value.uncertain
			continue
		}
		out = append(out, value)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func deduplicateAliasCoverage(in []jsresolution.CoverageIssue) []jsresolution.CoverageIssue {
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
