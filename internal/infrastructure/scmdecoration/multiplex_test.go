package scmdecoration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMultiplexDecoratorRoutesByProvider(t *testing.T) {
	decorator, err := NewMultiplexDecorator(&fakeGitCredentials{token: []byte("t"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	github, err := decorator.decoratorFor("github-actions")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := github.(*GitHubDecorator); !ok {
		t.Fatalf("github-actions routed to %T", github)
	}
	gitlab, err := decorator.decoratorFor("gitlab-ci")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := gitlab.(*GitLabDecorator); !ok {
		t.Fatalf("gitlab-ci routed to %T", gitlab)
	}
	// Same provider must return the cached instance, not a fresh adapter each call.
	again, err := decorator.decoratorFor("github")
	if err != nil {
		t.Fatal(err)
	}
	if again != github {
		t.Fatal("multiplex must cache one adapter per provider")
	}
}

func TestMultiplexDecoratorRejectsUnknownProvider(t *testing.T) {
	decorator, err := NewMultiplexDecorator(&fakeGitCredentials{token: []byte("t"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	err = decorator.Decorate(context.Background(), ports.PRDecoration{Provider: "svn", Target: ports.PRDecorationTarget{Repository: "a/b", CommitSHA: "c", PullRequest: "1", TargetBranch: "main"}})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error = %v, want validation for unknown provider", err)
	}
}

func TestMultiplexDecoratorDispatchesToTheRightForge(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotPath == "" {
			gotPath = r.URL.EscapedPath()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	// Point one GitLab adapter at the fake server and register it directly, proving Decorate routes by provider.
	gitlab, err := newGitLabDecorator(server.Client(), server.URL, gitlabCredentialHost, &fakeGitCredentials{token: []byte("t"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	decorator, err := NewMultiplexDecorator(&fakeGitCredentials{token: []byte("t"), ok: true})
	if err != nil {
		t.Fatal(err)
	}
	decorator.byProvider["gitlab"] = gitlab

	err = decorator.Decorate(context.Background(), ports.PRDecoration{
		Provider: "gitlab-ci", Gate: qualitygate.Result{Passed: true},
		Target: ports.PRDecorationTarget{Repository: "acme/widget", CommitSHA: "head", PullRequest: "7", TargetBranch: "main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotPath, "/projects/acme%2Fwidget") {
		t.Fatalf("first GitLab request path = %q, want the GitLab adapter to have handled it", gotPath)
	}
}
