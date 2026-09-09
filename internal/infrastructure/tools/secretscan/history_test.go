package secretscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
		}
		if f.Match == secret { // the raw secret must never leave the package
			t.Errorf("history finding must be redacted, leaked the raw secret")
		}
	}
	if !found {
		t.Fatalf("history scan must find the removed AWS key, got %+v", hist.Findings)
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
