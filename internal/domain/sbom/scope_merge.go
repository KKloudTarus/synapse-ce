package sbom

// MergeScope returns the scope a component keeps when two copies of it are merged into one: earlier is the scope
// of the copy already held, later the scope of the copy being folded in. Copies of one package come from
// different manifests (two Gradle modules, two pom.xml files, two install paths in one lockfile) or from
// different evidence sources, and which one arrives first is decided by the filesystem walk or by the
// producer's output order. That order is not a statement about the dependency, so it must not decide the scope
// (#1692): a module that declares the package for production ships it, whichever module was read first.
//
// The rule, highest rank first:
//   - production wins over every other scope;
//   - a scope the gate does not exempt (development, or any value IsBackgroundScope does not name) wins over a
//     background scope, so a background scope survives only when every copy is background and merging can
//     never hide a copy the gate would have counted;
//   - a background scope wins over an empty or unknown scope, which records no evidence either way.
//
// Equal ranks keep the earlier scope, so a merge stays stable: only the choice among background scopes, or
// between empty and unknown, still follows order, and none of those changes what the gate counts.
func MergeScope(earlier, later string) string {
	if scopeMergeRank(later) > scopeMergeRank(earlier) {
		return later
	}
	return earlier
}

// scopeMergeRank orders scopes for MergeScope.
func scopeMergeRank(s string) int {
	switch {
	case s == ScopeProduction:
		return 3
	case s == "" || s == ScopeUnknown:
		return 0
	case IsBackgroundScope(s):
		return 1
	default:
		return 2
	}
}
