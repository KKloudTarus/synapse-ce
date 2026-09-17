package projectanalysis

import "strings"

// BranchInfo names a branch and its lifecycle classification, for the branches read model.
type BranchInfo struct {
	Name string     `json:"name"`
	Kind BranchKind `json:"kind"`
}

// BranchKind classifies a branch by lifecycle. A long-lived branch (main, develop, a release line, or
// the project's configured default) accumulates history that is kept indefinitely; a short-lived branch
// (a feature or pull-request branch) is transient and its analyses are eligible for retention pruning.
type BranchKind string

const (
	BranchLongLived  BranchKind = "long_lived"
	BranchShortLived BranchKind = "short_lived"
)

// longLivedExact is the set of conventional long-lived branch names (case-insensitive).
var longLivedExact = map[string]bool{
	"main": true, "master": true, "develop": true, "development": true, "trunk": true, "default": true,
}

// longLivedPrefixes is the set of conventional long-lived branch prefixes (case-insensitive).
var longLivedPrefixes = []string{"release/", "releases/", "hotfix/", "hotfixes/", "support/", "maintenance/", "stable/"}

// ClassifyBranch returns the lifecycle kind of a branch. The project's configured default branch
// (SourceBinding.DefaultBranch) is always long-lived. A branch matching a well-known long-lived
// convention (main/master/develop, release/*, hotfix/*, support/*, ...) is long-lived. An empty or
// unrecognized branch is treated as long-lived so retention never prunes an analysis it cannot classify;
// only a branch positively recognized as short-lived becomes prune-eligible.
func ClassifyBranch(branch, defaultBranch string) BranchKind {
	b := strings.TrimPrefix(strings.TrimSpace(branch), "refs/heads/")
	if b == "" {
		return BranchLongLived
	}
	if d := strings.TrimPrefix(strings.TrimSpace(defaultBranch), "refs/heads/"); d != "" && strings.EqualFold(b, d) {
		return BranchLongLived
	}
	lower := strings.ToLower(b)
	if longLivedExact[lower] {
		return BranchLongLived
	}
	for _, prefix := range longLivedPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return BranchLongLived
		}
	}
	return BranchShortLived
}

// IsShortLivedBranch reports whether a branch is a transient feature/PR branch whose analyses are
// eligible for retention pruning.
func IsShortLivedBranch(branch, defaultBranch string) bool {
	return ClassifyBranch(branch, defaultBranch) == BranchShortLived
}
