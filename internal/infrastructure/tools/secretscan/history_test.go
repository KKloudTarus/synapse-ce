package secretscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRun runs a git command in dir, failing the test on error. Identity is passed inline so the test needs no
// global git config.
func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{
		"-C", dir,
		"-c", "user.email=test@example.invalid",
		"-c", "user.name=Test",
		"-c", "commit.gpgsign=false",
		"-c", "core.hooksPath=/dev/null", // the temp repo must not inherit the dev environment's git hooks
	}, args...)
	cmd := exec.Command("git", full...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// gitOut runs a git command in dir and returns its trimmed stdout, failing the test on error.
func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", full...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

func TestScanHistoryFindsRemovedSecret(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")

	// A committed AWS access key (not an "example" placeholder, so the allow-list does not skip it).
	const secret = "AKIAZ3ABCDEFGHIJKLMN"
	writeFile(t, dir, "config.py", "AWS_KEY = \""+secret+"\"\n")
	gitRun(t, dir, "add", "config.py")
	gitRun(t, dir, "commit", "-q", "-m", "add config")
	introCommit := gitOut(t, dir, "rev-parse", "HEAD") // the commit that introduced the secret

	// Remove the secret from the working tree in a later commit: HEAD is now clean.
	writeFile(t, dir, "config.py", "AWS_KEY = os.environ[\"AWS_KEY\"]\n")
	gitRun(t, dir, "add", "config.py")
	gitRun(t, dir, "commit", "-q", "-m", "move key to env")

	s := New()

	// HEAD-only scan must NOT find it (the working tree is clean).
	head, err := s.ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	for _, f := range head.Findings {
		if f.RuleID == "aws-access-key-id" {
			t.Errorf("HEAD scan must not find the removed secret, got %+v", head.Findings)
		}
	}

	// History scan MUST find it in the earlier commit's blob.
	hist, err := s.ScanHistory(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanHistory: %v", err)
	}
	found := false
	for _, f := range hist.Findings {
		if f.RuleID == "aws-access-key-id" {
			found = true
			if f.File != "config.py" {
				t.Errorf("finding path = %q, want config.py", f.File)
			}
			// D6.1: the hit is attributed to the commit that introduced it, with the author and date.
			if f.Commit != introCommit {
				t.Errorf("finding Commit = %q, want introducing commit %q", f.Commit, introCommit)
			}
			if f.Author != "Test" {
				t.Errorf("finding Author = %q, want Test", f.Author)
			}
			if f.FirstSeen == "" {
				t.Errorf("finding FirstSeen (author date) must be set")
			}
		}
		if f.Match == secret { // the raw secret must never leave the package
			t.Errorf("history finding must be redacted, leaked the raw secret")
		}
	}
	if !found {
		t.Fatalf("history scan must find the removed AWS key, got %+v", hist.Findings)
	}
}

// TestScanHistoryAttributesFirstIntroducingCommit: a secret introduced in commit 1, carried unchanged through
// a later commit, then removed, is attributed to the FIRST commit (not a later one that also carried it).
func TestScanHistoryAttributesFirstIntroducingCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")

	const secret = "AKIAZ3ABCDEFGHIJKLMN"
	// Commit 1: introduce the secret.
	writeFile(t, dir, "app.py", "AWS_KEY = \""+secret+"\"\n")
	gitRun(t, dir, "add", "app.py")
	gitRun(t, dir, "commit", "-q", "-m", "c1 introduce")
	firstCommit := gitOut(t, dir, "rev-parse", "HEAD")

	// Commit 2: add an unrelated line, the secret line (and thus its blob content at that path:line) persists.
	writeFile(t, dir, "app.py", "AWS_KEY = \""+secret+"\"\nOTHER = 1\n")
	gitRun(t, dir, "add", "app.py")
	gitRun(t, dir, "commit", "-q", "-m", "c2 unrelated change")

	// Commit 3: remove the secret. HEAD is now clean.
	writeFile(t, dir, "app.py", "OTHER = 1\n")
	gitRun(t, dir, "add", "app.py")
	gitRun(t, dir, "commit", "-q", "-m", "c3 remove")

	hist, err := New().ScanHistory(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanHistory: %v", err)
	}
	n := 0
	for _, f := range hist.Findings {
		if f.RuleID != "aws-access-key-id" {
			continue
		}
		n++
		if f.Commit != firstCommit {
			t.Errorf("Commit = %q, want the first-introducing commit %q", f.Commit, firstCommit)
		}
	}
	// Blob dedup: the secret at app.py:1 is one blob in c1 and another in c2, but it is reported ONCE.
	if n != 1 {
		t.Fatalf("expected exactly one attributed AWS-key finding, got %d: %+v", n, hist.Findings)
	}
}

func TestScanHistoryNonRepoErrors(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if _, err := New().ScanHistory(context.Background(), t.TempDir()); err == nil {
		t.Error("scanning a non-git directory must return an error")
	}
}

// TestScanHistoryTopoOrderBeatsDateSkew: the introducing (parent) commit is dated LATER than the child that
// removes the secret. A date-ordered walk would mis-credit the child; --topo-order --reverse credits the
// parent, which actually introduced the secret.
func TestScanHistoryTopoOrderBeatsDateSkew(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")

	const secret = "AKIAZ3ABCDEFGHIJKLMN"
	// Parent commit introduces the secret, dated in the future.
	writeFile(t, dir, "s.py", "AWS_KEY = \""+secret+"\"\n")
	gitRun(t, dir, "add", "s.py")
	gitRunEnv(t, dir, []string{"GIT_AUTHOR_DATE=2030-01-01T00:00:00", "GIT_COMMITTER_DATE=2030-01-01T00:00:00"}, "commit", "-q", "-m", "parent introduces")
	parent := gitOut(t, dir, "rev-parse", "HEAD")

	// Child removes it, dated in the past (earlier than the parent).
	writeFile(t, dir, "s.py", "AWS_KEY = env\n")
	gitRun(t, dir, "add", "s.py")
	gitRunEnv(t, dir, []string{"GIT_AUTHOR_DATE=2000-01-01T00:00:00", "GIT_COMMITTER_DATE=2000-01-01T00:00:00"}, "commit", "-q", "-m", "child removes")

	hist, err := New().ScanHistory(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanHistory: %v", err)
	}
	found := false
	for _, f := range hist.Findings {
		if f.RuleID == "aws-access-key-id" {
			found = true
			if f.Commit != parent {
				t.Errorf("Commit = %q, want the parent that introduced the secret %q", f.Commit, parent)
			}
			if !f.FromHistory {
				t.Errorf("history finding must set FromHistory")
			}
		}
	}
	if !found {
		t.Fatalf("history scan must find the removed secret")
	}
}

// gitRunEnv runs a git command with extra environment (e.g. GIT_AUTHOR_DATE), failing on error.
func gitRunEnv(t *testing.T, dir string, extraEnv []string, args ...string) {
	t.Helper()
	full := append([]string{
		"-C", dir,
		"-c", "user.email=test@example.invalid",
		"-c", "user.name=Test",
		"-c", "commit.gpgsign=false",
		"-c", "core.hooksPath=/dev/null",
	}, args...)
	cmd := exec.Command("git", full...)
	cmd.Env = append(append(os.Environ(), "GIT_TERMINAL_PROMPT=0"), extraEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
