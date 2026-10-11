package scmdecoration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// hostCredentials answers per host, like the connector store: each host has its own token and
// optional API base. It records which hosts were asked for.
type hostCredentials struct {
	mu    sync.Mutex
	byKey map[string]ports.GitCredential
	asked []string
}

func (h *hostCredentials) ResolveGitCredential(_ context.Context, host string) (ports.GitCredential, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.asked = append(h.asked, host)
	cred, ok := h.byKey[host]
	if !ok {
		return ports.GitCredential{}, false, nil
	}
	cred.Token = append([]byte(nil), cred.Token...)
	return cred, true, nil
}

// selfHostedServer is a TLS fake forge that serves handler under prefix and counts every request,
// including ones outside the prefix.
func selfHostedServer(t *testing.T, prefix string, handler http.HandlerFunc) (*httptest.Server, string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.Handle(prefix+"/", http.StripPrefix(prefix, handler))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return server, u.Host, &hits
}

func allowlistRules(t *testing.T, hosts ...string) selfhosted.Rules {
	t.Helper()
	list, err := selfhosted.ParseHostAllowlist(hosts)
	if err != nil {
		t.Fatal(err)
	}
	return selfhosted.Rules{Hosts: list}
}

// saasTrap is a SaaS API stand-in that fails the test if the self-hosted token reaches it.
func saasTrap(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("SaaS API was called: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestGitHubDecoratorPublishesToGHESThroughTheConnectorAPIBase(t *testing.T) {
	state := &fakeGitHubState{}
	server, host, _ := selfHostedServer(t, "/api/v3", state.handler)
	credentials := &hostCredentials{byKey: map[string]ports.GitCredential{
		host:         {Username: "x-access-token", Token: []byte("ghes-token"), APIBase: "https://" + host + "/api/v3"},
		"github.com": {Username: "x-access-token", Token: []byte("saas-token")},
	}}
	trap := saasTrap(t)
	decorator, err := newGitHubDecorator(trap.Client(), trap.URL, githubCredentialHost, credentials)
	if err != nil {
		t.Fatal(err)
	}
	decorator.selfHosted = newSelfHostedAPI("github", collectOptions([]Option{WithSelfHostedRules(allowlistRules(t, host)), withSelfHostedHTTPClient(server.Client())}))

	decoration := testDecoration("ghes summary")
	decoration.ForgeHost = host
	if err := decorator.Decorate(context.Background(), decoration); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.statusPosts != 1 || state.checkPosts != 1 || state.commentPosts != 1 {
		t.Fatalf("GHES writes status/check/comment = %d/%d/%d, want 1/1/1", state.statusPosts, state.checkPosts, state.commentPosts)
	}
	for _, header := range state.authHeaders {
		if header != "Bearer ghes-token" {
			t.Fatalf("GHES received authorization %q, want the GHES connector token", header)
		}
	}
	if len(credentials.asked) != 1 || credentials.asked[0] != host {
		t.Fatalf("credential lookups = %v, want only the configured API host", credentials.asked)
	}
}

func TestGitLabDecoratorPublishesToSelfManagedGitLabThroughTheConnectorAPIBase(t *testing.T) {
	state := &fakeGitLabState{}
	server, host, _ := selfHostedServer(t, "/gitlab/api/v4", state.handler)
	credentials := &hostCredentials{byKey: map[string]ports.GitCredential{
		host: {Username: "oauth2", Token: []byte("glpat-selfmanaged"), APIBase: "https://" + host + "/gitlab/api/v4"},
	}}
	trap := saasTrap(t)
	decorator, err := newGitLabDecorator(trap.Client(), trap.URL, gitlabCredentialHost, credentials)
	if err != nil {
		t.Fatal(err)
	}
	decorator.selfHosted = newSelfHostedAPI("gitlab", collectOptions([]Option{WithSelfHostedRules(allowlistRules(t, host)), withSelfHostedHTTPClient(server.Client())}))

	decoration := testDecoration("gitlab summary")
	decoration.ForgeHost = host
	if err := decorator.Decorate(context.Background(), decoration); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.statusPosts != 1 || state.notePosts != 1 {
		t.Fatalf("GitLab writes status/note = %d/%d, want 1/1", state.statusPosts, state.notePosts)
	}
	for _, token := range state.tokens {
		if token != "glpat-selfmanaged" {
			t.Fatalf("GitLab received PRIVATE-TOKEN %q", token)
		}
	}
}

func TestSelfHostedDecorationRefusedWithoutSendingTheToken(t *testing.T) {
	cases := []struct {
		name    string
		rules   func(host string) []Option
		apiBase func(host string) string
	}{
		{"operator allowlist no longer lists the host", func(string) []Option {
			return []Option{WithSelfHostedRules(allowlistRules(t, "ghe.other.example"))}
		}, func(host string) string { return "https://" + host + "/api/v3" }},
		{"empty operator allowlist", func(string) []Option {
			return []Option{WithSelfHostedRules(selfhosted.Rules{})}
		}, func(host string) string { return "https://" + host + "/api/v3" }},
		{"self-hosted decoration not enabled", func(string) []Option { return nil },
			func(host string) string { return "https://" + host + "/api/v3" }},
		{"stored base points at another host", func(host string) []Option {
			return []Option{WithSelfHostedRules(allowlistRules(t, host, "evil.example"))}
		}, func(string) string { return "https://evil.example/api/v3" }},
		{"stored base is http", func(host string) []Option {
			return []Option{WithSelfHostedRules(allowlistRules(t, host))}
		}, func(host string) string { return "http://" + host + "/api/v3" }},
		{"stored base is a GitLab API", func(host string) []Option {
			return []Option{WithSelfHostedRules(allowlistRules(t, host))}
		}, func(host string) string { return "https://" + host + "/api/v4" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &fakeGitHubState{}
			server, host, hits := selfHostedServer(t, "/api/v3", state.handler)
			credentials := &hostCredentials{byKey: map[string]ports.GitCredential{
				host: {Token: []byte("ghes-token"), APIBase: tc.apiBase(host)},
			}}
			trap := saasTrap(t)
			decorator, err := newGitHubDecorator(trap.Client(), trap.URL, githubCredentialHost, credentials)
			if err != nil {
				t.Fatal(err)
			}
			opts := append(tc.rules(host), withSelfHostedHTTPClient(server.Client()))
			decorator.selfHosted = newSelfHostedAPI("github", collectOptions(opts))
			decoration := testDecoration("summary")
			decoration.ForgeHost = host
			err = decorator.Decorate(context.Background(), decoration)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want validation", err)
			}
			if strings.Contains(err.Error(), "ghes-token") {
				t.Fatalf("error leaks the token: %v", err)
			}
			if hits.Load() != 0 {
				t.Fatalf("the self-hosted server received %d requests", hits.Load())
			}
		})
	}
}

func TestSelfHostedForgeWithoutAPIBaseKeepsTheSaaSDefault(t *testing.T) {
	state := &fakeGitHubState{}
	saas := httptest.NewServer(http.HandlerFunc(state.handler))
	defer saas.Close()
	credentials := &hostCredentials{byKey: map[string]ports.GitCredential{
		"git.mirror.example": {Token: []byte("clone-only-token")},
		"github.com":         {Token: []byte("saas-token")},
	}}
	decorator, err := NewGitHubDecorator(credentials, WithSelfHostedRules(allowlistRules(t, "git.mirror.example")))
	if err != nil {
		t.Fatal(err)
	}
	decorator.api = newJSONHTTPClient(saas.Client(), saas.URL)
	for _, forgeHost := range []string{"", "github.com", "git.mirror.example"} {
		decoration := testDecoration("summary")
		decoration.ForgeHost = forgeHost
		if err := decorator.Decorate(context.Background(), decoration); err != nil {
			t.Fatalf("forge host %q: %v", forgeHost, err)
		}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	for _, header := range state.authHeaders {
		if header != "Bearer saas-token" {
			t.Fatalf("SaaS API received %q, want only the github.com token", header)
		}
	}
}

func TestBitbucketRefusesADataCenterAPIBase(t *testing.T) {
	trap := saasTrap(t)
	credentials := &hostCredentials{byKey: map[string]ports.GitCredential{
		"bitbucket.corp.example": {Username: "bot", Token: []byte("bb-token"), APIBase: "https://bitbucket.corp.example/rest/api/1.0"},
	}}
	decorator, err := newBitbucketDecorator(trap.Client(), trap.URL, bitbucketCredentialHost, credentials)
	if err != nil {
		t.Fatal(err)
	}
	decoration := testDecoration("summary")
	decoration.ForgeHost = "bitbucket.corp.example"
	if err := decorator.Decorate(context.Background(), decoration); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want validation", err)
	}
}

func TestMultiplexPassesSelfHostedRulesToAdapters(t *testing.T) {
	decorator, err := NewMultiplexDecorator(&fakeGitCredentials{token: []byte("t"), ok: true}, WithSelfHostedRules(allowlistRules(t, "ghe.corp.example")))
	if err != nil {
		t.Fatal(err)
	}
	github, err := decorator.decoratorFor("github-actions")
	if err != nil {
		t.Fatal(err)
	}
	if gh, ok := github.(*GitHubDecorator); !ok || gh.selfHosted == nil {
		t.Fatalf("github adapter = %T without self-hosted support", github)
	}
	gitlab, err := decorator.decoratorFor("gitlab-ci")
	if err != nil {
		t.Fatal(err)
	}
	if gl, ok := gitlab.(*GitLabDecorator); !ok || gl.selfHosted == nil {
		t.Fatalf("gitlab adapter = %T without self-hosted support", gitlab)
	}
	plain, err := NewGitHubDecorator(&fakeGitCredentials{token: []byte("t"), ok: true})
	if err != nil || plain.selfHosted != nil {
		t.Fatalf("a decorator without rules must stay SaaS-only: %v", err)
	}
}
