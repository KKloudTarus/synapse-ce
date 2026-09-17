package projectanalysis

import "testing"

func TestClassifyBranch(t *testing.T) {
	cases := []struct {
		branch, defaultBranch string
		want                  BranchKind
	}{
		{"main", "", BranchLongLived},
		{"master", "", BranchLongLived},
		{"develop", "", BranchLongLived},
		{"MAIN", "", BranchLongLived},
		{"refs/heads/main", "", BranchLongLived},
		{"release/2.1", "", BranchLongLived},
		{"hotfix/urgent", "", BranchLongLived},
		{"support/1.x", "", BranchLongLived},
		{"trunk", "main", BranchLongLived},
		// The project default is long-lived even when it is an unconventional name.
		{"production", "production", BranchLongLived},
		{"production", "refs/heads/production", BranchLongLived},
		// Feature and PR branches are short-lived.
		{"feature/login", "main", BranchShortLived},
		{"pr-42", "main", BranchShortLived},
		{"nghia/experiment", "main", BranchShortLived},
		{"release-notes", "main", BranchShortLived}, // no trailing slash: not a release line
		// Unknown/empty is retain-safe (long-lived) so retention never prunes what it cannot classify.
		{"", "main", BranchLongLived},
		{"   ", "main", BranchLongLived},
	}
	for _, c := range cases {
		if got := ClassifyBranch(c.branch, c.defaultBranch); got != c.want {
			t.Errorf("ClassifyBranch(%q, %q) = %q, want %q", c.branch, c.defaultBranch, got, c.want)
		}
	}
}

func TestIsShortLivedBranch(t *testing.T) {
	if !IsShortLivedBranch("feature/x", "main") {
		t.Fatal("feature/x must be short-lived")
	}
	if IsShortLivedBranch("main", "main") {
		t.Fatal("main must not be short-lived")
	}
	if IsShortLivedBranch("", "main") {
		t.Fatal("an unclassifiable empty branch must not be pruned")
	}
}
