package acquire

import (
	"context"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeGitCreds is a GitCredentialResolver that returns a credential only for one host, so a test
// exercises both the authenticated (host matches) and unauthenticated (host does not) paths.
type fakeGitCreds struct {
	host, user, token string
}

func (f fakeGitCreds) ResolveGitCredential(_ context.Context, host string) (ports.GitCredential, bool, error) {
	if host == f.host {
		return ports.GitCredential{Username: f.user, Token: []byte(f.token)}, true, nil
	}
	return ports.GitCredential{}, false, nil
}

// TestGitAuthInjectsTokenViaAskpassNotArgv proves the injection contract without a network: the token
// never appears in the clone URL (only the username does), it is delivered through GIT_ASKPASS, and the
// askpass helper emits exactly the token when run with the returned environment.
func TestGitAuthInjectsTokenViaAskpassNotArgv(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	const host, user, token = "ghe.example.com", "x-access-token", "s3cr3t-pat-value"
	a := New().WithGitCredentialResolver(fakeGitCreds{host: host, user: user, token: token})

	cloneURL, authEnv, roPaths, cleanup, err := a.gitAuth(context.Background(), "https://ghe.example.com/org/repo.git")
	if err != nil {
		t.Fatalf("gitAuth: %v", err)
	}
	defer cleanup()

	if strings.Contains(cloneURL, token) {
		t.Fatalf("token must never be in the clone URL: %q", cloneURL)
	}
	if !strings.Contains(cloneURL, user+"@") {
		t.Fatalf("clone URL must carry the username userinfo: %q", cloneURL)
	}
	var askpass, tokenFileEnv string
	for _, kv := range authEnv {
		if strings.HasPrefix(kv, "GIT_ASKPASS=") {
			askpass = strings.TrimPrefix(kv, "GIT_ASKPASS=")
		}
		if strings.HasPrefix(kv, "SYNAPSE_GIT_TOKEN_FILE=") {
			tokenFileEnv = kv
		}
	}
	if askpass == "" || tokenFileEnv == "" {
		t.Fatalf("authEnv must set GIT_ASKPASS and SYNAPSE_GIT_TOKEN_FILE: %v", authEnv)
	}
	if len(roPaths) != 1 {
		t.Fatalf("roPaths must carry the credential dir for the sandbox bind: %v", roPaths)
	}
	// Running the helper with the token-file env (as git will) must emit exactly the token.
	cmd := exec.Command(askpass, "Password: ")
	cmd.Env = append(os.Environ(), tokenFileEnv)
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("askpass with token-file env: %v", err)
	}
	if strings.TrimSpace(string(got)) != token {
		t.Fatalf("askpass emitted %q, want the token", strings.TrimSpace(string(got)))
	}
}

// TestGitAuthNoConnectorIsUnauthenticated: a host with no connector, and a nil resolver, both clone
// with the original URL and no auth environment (public-repo path, unchanged behavior).
func TestGitAuthNoConnectorIsUnauthenticated(t *testing.T) {
	orig := "https://github.com/org/public.git"
	// resolver present but host does not match
	a := New().WithGitCredentialResolver(fakeGitCreds{host: "ghe.example.com", user: "u", token: "t"})
	url, env, ro, cleanup, err := a.gitAuth(context.Background(), orig)
	cleanup()
	if err != nil || url != orig || env != nil || ro != nil {
		t.Fatalf("unmatched host must clone unauthenticated: url=%q env=%v err=%v", url, env, err)
	}
	// no resolver at all
	url, env, _, cleanup2, err := New().gitAuth(context.Background(), orig)
	cleanup2()
	if err != nil || url != orig || env != nil {
		t.Fatalf("nil resolver must clone unauthenticated: url=%q env=%v err=%v", url, env, err)
	}
}

// TestAcquireGitPrivateRepoEndToEnd stands up a real git smart-HTTP server (git-http-backend) behind
// HTTP basic auth and proves the acquirer clones a PRIVATE repository ONLY when a connector supplies the
// token: the same clone with no connector is refused 401. This exercises the whole injection path through
// real git, including the second (git-upload-pack) request that reuses the cached credential.
func TestAcquireGitPrivateRepoEndToEnd(t *testing.T) {
	backend := "/usr/lib/git-core/git-http-backend"
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
	// git verifies the httptest self-signed TLS cert unless told not to; the acquirer inherits the
	// process env, so this is the only knob the test needs. Scoped to the test via t.Setenv.
	t.Setenv("GIT_SSL_NO_VERIFY", "true")

	// A clean HOME carrying an ambient `credential.helper=store`: if any networked git op (clone OR the
	// comparison fetch) fails to blank the helper, git's `credential approve` writes the PAT here in
	// plaintext. The acquirer blanks credential.helper on both, so this file must never appear (QA #Q2).
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[credential]\n\thelper = store\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(home, ".git-credentials")

	root := t.TempDir()
	repo := filepath.Join(root, "repo.git")
	runGit(t, "", "init", "--bare", repo)
	work := t.TempDir()
	// Disable any ambient core.hooksPath (this repo installs a commit-msg hook globally) so the
	// throwaway fixture repo can commit a plain message without the Conventional Commits gate.
	runGit(t, work, "init")
	runGit(t, work, "config", "core.hooksPath", filepath.Join(t.TempDir(), "no-hooks"))
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte("module example.com/private\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", ".")
	runGit(t, work, "-c", "user.email=t@example.com", "-c", "user.name=tester", "commit", "-m", "chore: seed fixture repo")
	runGit(t, work, "-c", "http.sslVerify=false", "push", repo, "HEAD:refs/heads/main")

	const user, token = "x-access-token", "clone-pat-1234"
	authed := false
	handler := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != token {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authed = true
		handler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	host, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	cloneURL := srv.URL + "/repo.git"

	// With the connector: the private clone succeeds and the work tree carries the committed file.
	// allowInternalHosts is a test-only escape: httptest binds loopback, which the SSRF guard would
	// otherwise refuse. No composition root sets it.
	// BaseRef drives resolveComparison, so the comparison fetch (the other networked op) also runs
	// authenticated and its credential hardening is exercised, not just the clone's.
	a := New().WithGitCredentialResolver(fakeGitCreds{host: host, user: user, token: token})
	a.allowInternalHosts = true
	ws, err := a.Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetGit, Value: cloneURL, Ref: "main", BaseRef: "main"})
	if err != nil {
		t.Fatalf("authenticated clone should succeed, got: %v", err)
	}
	defer ws.Close()
	if !authed {
		t.Fatal("server never saw an authenticated request")
	}
	if _, err := os.Stat(filepath.Join(ws.Dir, "go.mod")); err != nil {
		t.Fatalf("cloned workspace must contain the repo file: %v", err)
	}
	// The ambient credential.helper=store must never have captured the PAT, from either the clone or the
	// comparison fetch.
	if _, err := os.Stat(credFile); !os.IsNotExist(err) {
		t.Fatalf("the PAT must not be persisted to an ambient credential store (%s exists: %v)", credFile, err)
	}
	// The cloned remote URL must carry the username only, never the token.
	cfg, _ := os.ReadFile(filepath.Join(ws.Dir, ".git", "config"))
	if strings.Contains(string(cfg), token) {
		t.Fatal("the token must not appear in the cloned .git/config")
	}

	// Without the connector: the same private clone is refused (401), never a silent empty success.
	noConn := New()
	noConn.allowInternalHosts = true
	if _, err := noConn.Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetGit, Value: cloneURL, Ref: "main"}); err == nil {
		t.Fatal("a private clone with no connector must fail, not succeed unauthenticated")
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}
