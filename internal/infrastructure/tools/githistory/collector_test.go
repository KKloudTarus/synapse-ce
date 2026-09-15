package githistory

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v: %s", args, err, string(out))
		}
	}

	run("init")
	run("config", "user.name", "Test")
	run("config", "user.email", "test@example.com")
	return dir
}

func commitFile(t *testing.T, dir, file, content, msg string) {
	t.Helper()
	fullPath := filepath.Join(dir, file)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("writefile: %v", err)
	}
	cmd := exec.Command("git", "-C", dir, "add", file)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add %s failed: %v: %s", file, err, string(out))
	}
	cmd = exec.Command("git", "-C", dir, "commit", "-m", msg)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit %s failed: %v: %s", msg, err, string(out))
	}
}

func TestCollector_ReachesRoot(t *testing.T) {
	dir := initGitRepo(t)
	commitFile(t, dir, "a.go", "package a", "root commit")
	commitFile(t, dir, "b.go", "package b", "second commit")

	c := New()
	res, err := c.CollectHistory(context.Background(), dir, "", 10)
	if err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}

	if !res.Available {
		t.Fatalf("expected available, got reason=%s", res.Reason)
	}
	if !res.ReachedRoot {
		t.Errorf("expected reachedRoot=true")
	}
	if res.Evaluated != 2 {
		t.Errorf("expected evaluated=2, got %d", res.Evaluated)
	}
	if len(res.Commits) != 2 {
		t.Fatalf("expected 2 commits, got %d", len(res.Commits))
	}
	if len(res.Commits[0].TouchedPaths) != 1 || res.Commits[0].TouchedPaths[0] != "b.go" ||
		len(res.Commits[1].TouchedPaths) != 1 || res.Commits[1].TouchedPaths[0] != "a.go" {
		t.Fatalf("unexpected root-history touches: %+v", res.Commits)
	}
	// Oldest commit is the root commit
	if res.Commits[1].FirstParentID != "" {
		t.Errorf("root commit should have empty first parent, got %s", res.Commits[1].FirstParentID)
	}
}

func TestCollector_MergeFirstParentOnly(t *testing.T) {
	dir := initGitRepo(t)
	commitFile(t, dir, "base.go", "package base", "init")

	// Create side branch
	cmd := exec.Command("git", "-C", dir, "checkout", "-b", "side")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("checkout side: %v: %s", err, string(out))
	}
	commitFile(t, dir, "side.go", "package side", "side commit")

	// Back to main branch
	cmd = exec.Command("git", "-C", dir, "checkout", "master")
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("git", "-C", dir, "checkout", "main")
		if err := cmd.Run(); err != nil {
			t.Fatalf("checkout main/master failed")
		}
	}
	commitFile(t, dir, "main.go", "package main", "main commit")

	// Merge side branch
	cmd = exec.Command("git", "-C", dir, "merge", "--no-ff", "side", "-m", "merge side")
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git merge failed: %v: %s", err, string(out))
	}

	c := New()
	res, err := c.CollectHistory(context.Background(), dir, "", 10)
	if err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}

	if !res.Available {
		t.Fatalf("expected available, got reason=%s", res.Reason)
	}

	// First parent history consists of: merge commit, main commit, init commit (3 commits)
	// Side commit is NOT on first-parent chain!
	if res.Evaluated != 3 {
		t.Errorf("expected 3 first-parent commits, got %d", res.Evaluated)
	}
	if len(res.Commits[0].TouchedPaths) != 1 || res.Commits[0].TouchedPaths[0] != "side.go" {
		t.Fatalf("merge must be counted once against its first parent, got %+v", res.Commits[0])
	}
}

func TestCollector_DirtyWorktree(t *testing.T) {
	dir := initGitRepo(t)
	commitFile(t, dir, "tracked.go", "package main", "commit tracked")

	// Modify tracked file without committing
	if err := os.WriteFile(filepath.Join(dir, "tracked.go"), []byte("package main // modified"), 0644); err != nil {
		t.Fatalf("write modified: %v", err)
	}

	c := New()
	res, err := c.CollectHistory(context.Background(), dir, "", 10)
	if err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}
	if res.Available {
		t.Fatal("expected unavailable for dirty worktree")
	}
	if !res.DirtyWorktree || res.Reason != "dirty_worktree" {
		t.Errorf("expected dirty_worktree reason, got %s", res.Reason)
	}
}

func TestCollector_DepthTooSmall(t *testing.T) {
	c := New()
	res, err := c.CollectHistory(context.Background(), t.TempDir(), "", 1)
	if err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}
	if res.Available || res.Reason != "depth_too_small_configure_min_2" {
		t.Errorf("expected depth_too_small reason, got %+v", res)
	}
}

func TestCollector_RejectsMismatchedExpectedHead(t *testing.T) {
	dir := initGitRepo(t)
	commitFile(t, dir, "a.go", "package a", "root")

	res, err := New().CollectHistory(context.Background(), dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10)
	if err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}
	if res.Available || res.Reason != "head_commit_mismatch" || res.HeadCommit == "" {
		t.Fatalf("mismatched head result = %+v", res)
	}
}

func TestCollector_MarksBoundedWindowBeforeRoot(t *testing.T) {
	dir := initGitRepo(t)
	commitFile(t, dir, "a.go", "package a", "one")
	commitFile(t, dir, "b.go", "package b", "two")
	commitFile(t, dir, "c.go", "package c", "three")

	// depth includes the comparison boundary, so depth=3 evaluates two commits.
	res, err := New().CollectHistory(context.Background(), dir, "", 3)
	if err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}
	if !res.Available || res.Evaluated != 2 || res.ReachedRoot {
		t.Fatalf("bounded result = %+v", res)
	}
	if len(res.Commits) != 2 || res.Commits[1].FirstParentID == "" {
		t.Fatalf("window lost its oldest boundary parent: %+v", res.Commits)
	}
}

func TestCollector_RenameCountsOldAndNewPaths(t *testing.T) {
	dir := initGitRepo(t)
	commitFile(t, dir, "old.go", "package renamed", "root")
	if out, err := exec.Command("git", "-C", dir, "mv", "old.go", "new.go").CombinedOutput(); err != nil {
		t.Fatalf("git mv: %v: %s", err, string(out))
	}
	cmd := exec.Command("git", "-C", dir, "commit", "-m", "rename")
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit rename: %v: %s", err, string(out))
	}

	res, err := New().CollectHistory(context.Background(), dir, "", 10)
	if err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}
	if !res.Available || len(res.Commits) < 1 {
		t.Fatalf("rename result = %+v", res)
	}
	got := res.Commits[0].TouchedPaths
	if len(got) != 2 || got[0] != "new.go" || got[1] != "old.go" {
		t.Fatalf("rename paths = %v, want delete/add identities", got)
	}
}

func TestCollector_RejectsExternalGitLayouts(t *testing.T) {
	t.Run("linked git directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: ../outside\n"), 0600); err != nil {
			t.Fatal(err)
		}
		res, err := New().CollectHistory(context.Background(), dir, "", 10)
		if err != nil {
			t.Fatalf("CollectHistory: %v", err)
		}
		if res.Available || res.Reason != "external_git_directory" {
			t.Fatalf("linked layout result = %+v", res)
		}
	})

	t.Run("alternate objects", func(t *testing.T) {
		dir := initGitRepo(t)
		commitFile(t, dir, "a.go", "package a", "root")
		infoDir := filepath.Join(dir, ".git", "objects", "info")
		if err := os.MkdirAll(infoDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(infoDir, "alternates"), []byte("../../outside\n"), 0600); err != nil {
			t.Fatal(err)
		}
		res, err := New().CollectHistory(context.Background(), dir, "", 10)
		if err != nil {
			t.Fatalf("CollectHistory: %v", err)
		}
		if res.Available || res.Reason != "external_git_objects" {
			t.Fatalf("alternate layout result = %+v", res)
		}
	})
}
