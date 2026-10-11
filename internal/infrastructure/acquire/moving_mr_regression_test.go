package acquire

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditQueuedMRKeepsOldSHAAfterTargetRefAdvances(t *testing.T) {
	backend := "/usr/lib/git-core/git-http-backend"
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
	t.Setenv("GIT_SSL_NO_VERIFY", "true")

	root := t.TempDir()
	repo := filepath.Join(root, "repo.git")
	git(t, root, "init", "--bare", repo)
	work := t.TempDir()
	git(t, work, "init", "-b", "main")
	git(t, work, "config", "user.email", "test@example.com")
	git(t, work, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(work, "state.txt"), []byte("main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, work, "add", "state.txt")
	git(t, work, "commit", "-m", "seed")
	git(t, work, "remote", "add", "origin", repo)
	git(t, work, "push", "origin", "main")
	git(t, repo, "symbolic-ref", "HEAD", "refs/heads/main")

	baseSHA := strings.TrimSpace(git(t, work, "rev-parse", "HEAD"))
	git(t, work, "checkout", "-b", "fork-feature")
	if err := os.WriteFile(filepath.Join(work, "state.txt"), []byte("fork\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, work, "commit", "-am", "fork")
	sha := strings.TrimSpace(git(t, work, "rev-parse", "HEAD"))
	// Deliberately do NOT publish fork-feature as a normal branch in the target.
	git(t, work, "push", "origin", "HEAD:refs/merge-requests/7/head")

	// Simulate a second push before the worker claims the first delivery.
	if err := os.WriteFile(filepath.Join(work, "state.txt"), []byte("new push\n"), 0600); err != nil {
		t.Fatal(err)
	}
	git(t, work, "commit", "-am", "advance MR")
	git(t, work, "push", "origin", "HEAD:refs/merge-requests/7/head")
	git(t, repo, "config", "uploadpack.allowReachableSHA1InWant", "true")
	handler := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()

	a := New()
	a.allowInternalHosts = true
	ws, err := a.Acquire(context.Background(), ports.AcquireRequest{
		Kind: ports.TargetGit, Value: srv.URL + "/repo.git",
		Ref: "fork-feature", FetchRef: "refs/merge-requests/7/head",
		Commit: sha, DisableGitCredentials: true, BaseRef: "main",
	})
	if err != nil {
		t.Fatalf("acquire target-side MR ref: %v", err)
	}
	defer ws.Close()
	if ws.BaseCommit != baseSHA || ws.MergeBase != baseSHA {
		t.Fatalf("fork comparison base=%q mergeBase=%q want=%q", ws.BaseCommit, ws.MergeBase, baseSHA)
	}
	if ws.Commit != sha {
		t.Fatalf("MR checkout commit = %q, want %q", ws.Commit, sha)
	}
	body, err := os.ReadFile(filepath.Join(ws.Dir, "state.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "fork\n" {
		t.Fatalf("MR checkout body = %q, want fork", body)
	}
}
