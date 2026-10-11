package acquire

import (
	"context"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAcquireLocal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ws, err := New().Acquire(context.Background(), ports.AcquireRequest{Kind: "local", Value: dir})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if ws.Dir != dir {
		t.Errorf("workspace dir = %q, want %q", ws.Dir, dir)
	}
	if err := ws.Close(); err != nil { // local has no cleanup
		t.Errorf("Close: %v", err)
	}
}

func TestAcquireLocalMissing(t *testing.T) {
	_, err := New().Acquire(context.Background(), ports.AcquireRequest{Kind: "local", Value: filepath.Join(t.TempDir(), "nope")})
	if err == nil {
		t.Fatal("want error for missing path")
	}
}

func TestAcquireLocalRejectsSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := New().Acquire(context.Background(), ports.AcquireRequest{Kind: "local", Value: link}); err == nil {
		t.Fatal("want error: symlinked target root must be refused")
	}
}

func TestAcquireUnknownAndUnimplementedKinds(t *testing.T) {
	for _, kind := range []string{"archive", "image", "bogus"} {
		if _, err := New().Acquire(context.Background(), ports.AcquireRequest{Kind: kind, Value: "x"}); err == nil {
			t.Errorf("kind %q: want error", kind)
		}
	}
}

func TestAcquireGitPinnedMergeRequestRef(t *testing.T) {
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

	git(t, work, "checkout", "-b", "fork-feature")
	if err := os.WriteFile(filepath.Join(work, "state.txt"), []byte("fork\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, work, "commit", "-am", "fork")
	sha := strings.TrimSpace(git(t, work, "rev-parse", "HEAD"))
	// Deliberately do NOT publish fork-feature as a normal branch in the target.
	git(t, work, "push", "origin", "HEAD:refs/merge-requests/7/head")

	handler := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()

	a := New()
	a.allowInternalHosts = true
	ws, err := a.Acquire(context.Background(), ports.AcquireRequest{
		Kind: ports.TargetGit, Value: srv.URL + "/repo.git",
		Ref: "fork-feature", FetchRef: "refs/merge-requests/7/head",
		Commit: sha, DisableGitCredentials: true,
	})
	if err != nil {
		t.Fatalf("acquire target-side MR ref: %v", err)
	}
	defer ws.Close()
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

func TestResolveComparisonUsesFetchedBaseRef(t *testing.T) {
	repo := t.TempDir()
	git(t, repo, "init", "-b", "main")
	git(t, repo, "config", "user.email", "test@example.com")
	git(t, repo, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "main.go")
	git(t, repo, "commit", "-m", "base")
	git(t, repo, "checkout", "-b", "feature")
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("feature\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "commit", "-am", "feature")
	bare := filepath.Join(t.TempDir(), "remote.git")
	git(t, repo, "init", "--bare", bare)
	git(t, repo, "remote", "add", "origin", bare)
	git(t, repo, "push", "--all", "origin")

	acquirer := New().WithComparisonDepth(16)
	workspace := t.TempDir()
	git(t, workspace, "clone", "--depth", "1", "--branch", "feature", "file://"+bare, ".")
	head := strings.TrimSpace(git(t, workspace, "rev-parse", "HEAD"))
	base, mergeBase := acquirer.resolveComparison(context.Background(), workspace, "https://example.invalid/repo.git", nil, nil, head, "feature", "main", "")
	if base == "" || mergeBase == "" {
		t.Fatalf("base=%q mergeBase=%q, want resolved comparison", base, mergeBase)
	}
	if got := strings.TrimSpace(git(t, workspace, "rev-parse", "refs/synapse-comparison/base")); got != base {
		t.Fatalf("stored base=%q, want %q", got, base)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	// Run git without the developer's global and system configuration. A machine-level
	// core.hooksPath or commit template makes these fixtures fail for one engineer and pass for
	// another, which is worse than either outcome: the suite stops meaning the same thing
	// everywhere.
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestValidateGitURL(t *testing.T) {
	ok := []string{"https://github.com/x/y.git"}
	for _, u := range ok {
		if err := validateGitURL(u); err != nil {
			t.Errorf("validateGitURL(%q) = %v, want nil", u, err)
		}
	}
	// http:// is now rejected (MITM-able, same as git://) – https only.
	bad := []string{"", "-x", "http://h/x", "git://h/x", "ssh://h/x", "git@github.com:x/y.git", "ext::sh -c id", "file:///etc/passwd", "/local/path"}
	for _, u := range bad {
		if err := validateGitURL(u); err == nil {
			t.Errorf("validateGitURL(%q) = nil, want error", u)
		}
	}
}

func TestValidateGitRef(t *testing.T) {
	ok := []string{"", "main", "v1.2.3", "release-2.x", "feature/foo", "1.0.0"}
	for _, r := range ok {
		if err := validateGitRef(r); err != nil {
			t.Errorf("validateGitRef(%q) = %v, want nil", r, err)
		}
	}
	// Leading '-' is option injection (e.g. --upload-pack); spaces/meta are rejected.
	bad := []string{"-x", "--upload-pack=sh", "a b", "a;b", "a$(id)", "../x", "a\tb"}
	for _, r := range bad {
		if err := validateGitRef(r); err == nil {
			t.Errorf("validateGitRef(%q) = nil, want error", r)
		}
	}
}

func TestRejectInternalAcquisitionHost(t *testing.T) {
	// loopback + link-local (incl. cloud metadata) must be refused; public + RFC1918 allowed.
	for _, h := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0"} {
		if err := rejectInternalAcquisitionHost(h); err == nil {
			t.Errorf("host %q (loopback/link-local) must be refused", h)
		}
	}
	for _, h := range []string{"140.82.112.3" /*github*/, "10.0.0.5" /*internal git, allowed*/} {
		if err := rejectInternalAcquisitionHost(h); err != nil {
			t.Errorf("host %q should be allowed, got %v", h, err)
		}
	}
}
