package bitbucket

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type commitTransport func(*http.Request) (*http.Response, error)

func (f commitTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type commitCredentials struct {
	calls int
}

func (c *commitCredentials) ResolveGitCredential(ctx context.Context, host string) (ports.GitCredential, bool, error) {
	c.calls++
	tenant, _ := shared.TenantFrom(ctx)
	if host != "bitbucket.org" || tenant != "tenant" {
		return ports.GitCredential{}, false, errors.New("wrong credential scope")
	}
	return ports.GitCredential{Username: "reader", Token: []byte("fixture-token")}, true, nil
}

func TestCommitResolverUsesStoredCloudRepositoryAndForkHasNoCredentials(t *testing.T) {
	for _, fork := range []bool{false, true} {
		credentials := &commitCredentials{}
		resolver, err := NewCommitResolver(credentials)
		if err != nil {
			t.Fatal(err)
		}
		resolver.client.Transport = commitTransport(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodGet || req.URL.String() != "https://api.bitbucket.org/2.0/repositories/trusted/app/commit/aaaaaaaaaaaa?fields=hash" {
				t.Fatalf("unsafe lookup: %s %s", req.Method, req.URL)
			}
			user, password, auth := req.BasicAuth()
			if fork && auth || !fork && (!auth || user != "reader" || password != "fixture-token") {
				t.Fatalf("incorrect credential policy: fork=%v auth=%v", fork, auth)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"hash":"` + strings.Repeat("a", 40) + `"}`))}, nil
		})
		sha, err := resolver.ResolveBitbucketCommit(shared.WithTenant(context.Background(), "tenant"), "https://bitbucket.org/trusted/app.git", strings.Repeat("A", 12), fork)
		if err != nil || sha != strings.Repeat("a", 40) || fork && credentials.calls != 0 {
			t.Fatalf("sha=%q err=%v credential lookups=%d", sha, err, credentials.calls)
		}
	}
}

func TestCommitResolverRejectsUnsafeSourcesBeforeAnyRequest(t *testing.T) {
	resolver, _ := NewCommitResolver(&commitCredentials{})
	resolver.client.Transport = commitTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe source reached transport")
		return nil, nil
	})
	for _, source := range []string{
		"http://bitbucket.org/a/b", "https://evil.example/a/b", "https://bitbucket.org.evil.example/a/b",
		"https://user:secret@bitbucket.org/a/b", "https://bitbucket.org:443/a/b", "https://bitbucket.org/a/b?x=1",
		"https://bitbucket.org/a/b#x", "https://bitbucket.org/a/../b", "https://bitbucket.org/a/%2e%2e", "https://bitbucket.org/a/b/",
	} {
		if _, err := resolver.ResolveBitbucketCommit(context.Background(), source, strings.Repeat("a", 12), true); err == nil {
			t.Errorf("accepted unsafe source %q", source)
		}
	}
	for _, prefix := range []string{"", strings.Repeat("a", 11), strings.Repeat("a", 13), "--optionaaaa", "aaaaaaaaaaaz"} {
		if _, err := resolver.ResolveBitbucketCommit(context.Background(), "https://bitbucket.org/a/b", prefix, true); err == nil {
			t.Errorf("accepted unsafe prefix %q", prefix)
		}
	}
}

func TestCommitResolverBoundsResponsesAndSanitizesErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"mismatch", `{"hash":"` + strings.Repeat("b", 40) + `"}`, 200},
		{"short", `{"hash":"` + strings.Repeat("a", 12) + `"}`, 200},
		{"malformed", "sensitive-upstream-body", 200},
		{"oversized", strings.Repeat("sensitive-upstream-body", 300), 200},
		{"unavailable", "sensitive-upstream-body", 503},
		{"ambiguous", "sensitive-upstream-body", 409},
		{"redirect", "sensitive-upstream-body", 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver, _ := NewCommitResolver(&commitCredentials{})
			resolver.client.Transport = commitTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			if sha, err := resolver.ResolveBitbucketCommit(context.Background(), "https://bitbucket.org/a/b", strings.Repeat("a", 12), true); err == nil || sha != "" || strings.Contains(err.Error(), "sensitive-upstream-body") {
				t.Fatalf("unsafe response: sha=%q err=%v", sha, err)
			}
		})
	}
	resolver, _ := NewCommitResolver(&commitCredentials{})
	resolver.client.Transport = commitTransport(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, errors.New("fixture-token transport failure")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveBitbucketCommit(ctx, "https://bitbucket.org/a/b", strings.Repeat("a", 12), true); err == nil || strings.Contains(err.Error(), "fixture-token") {
		t.Fatalf("unsanitized canceled lookup: %v", err)
	}
}

func TestCommitResolverDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer server.Close()
	resolver, _ := NewCommitResolver(&commitCredentials{})
	resolver.client.Transport = commitTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{server.URL}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if _, err := resolver.ResolveBitbucketCommit(context.Background(), "https://bitbucket.org/a/b", strings.Repeat("a", 12), true); err == nil || redirected {
		t.Fatalf("redirect accepted: err=%v redirected=%v", err, redirected)
	}
}
