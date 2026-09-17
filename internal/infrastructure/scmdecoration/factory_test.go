package scmdecoration

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestForProviderSelectsOwnedAdapter(t *testing.T) {
	creds := &fakeGitCredentials{token: []byte("t"), ok: true}
	cases := map[string]any{
		"github":              (*GitHubDecorator)(nil),
		"github-actions":      (*GitHubDecorator)(nil),
		"gitlab":              (*GitLabDecorator)(nil),
		"gitlab-ci":           (*GitLabDecorator)(nil),
		"bitbucket":           (*BitbucketDecorator)(nil),
		"bitbucket-pipelines": (*BitbucketDecorator)(nil),
	}
	for provider, want := range cases {
		got, err := ForProvider(provider, creds)
		if err != nil {
			t.Fatalf("ForProvider(%q) error = %v", provider, err)
		}
		switch want.(type) {
		case *GitHubDecorator:
			if _, ok := got.(*GitHubDecorator); !ok {
				t.Fatalf("ForProvider(%q) = %T, want *GitHubDecorator", provider, got)
			}
		case *GitLabDecorator:
			if _, ok := got.(*GitLabDecorator); !ok {
				t.Fatalf("ForProvider(%q) = %T, want *GitLabDecorator", provider, got)
			}
		case *BitbucketDecorator:
			if _, ok := got.(*BitbucketDecorator); !ok {
				t.Fatalf("ForProvider(%q) = %T, want *BitbucketDecorator", provider, got)
			}
		}
	}
}

func TestForProviderRejectsUnsupported(t *testing.T) {
	if _, err := ForProvider("jenkins", &fakeGitCredentials{token: []byte("t"), ok: true}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error = %v, want validation for unsupported provider", err)
	}
}

func TestCredentialHostForProvider(t *testing.T) {
	cases := map[string]string{"github-actions": githubCredentialHost, "gitlab-ci": gitlabCredentialHost, "bitbucket-pipelines": bitbucketCredentialHost}
	for provider, want := range cases {
		got, ok := CredentialHostForProvider(provider)
		if !ok || got != want {
			t.Fatalf("CredentialHostForProvider(%q) = %q,%v want %q", provider, got, ok, want)
		}
	}
	if _, ok := CredentialHostForProvider("svn"); ok {
		t.Fatal("CredentialHostForProvider must reject an unsupported provider")
	}
}

func TestStaticCredentialResolverIsHostScopedAndCopiesToken(t *testing.T) {
	token := []byte("secret-token")
	resolver, err := NewStaticCredentialResolver("GitHub.com", "x-access-token", token)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the caller's slice must not change what the resolver returns (defensive copy).
	token[0] = 'X'

	got, ok, err := resolver.ResolveGitCredential(context.Background(), "github.com")
	if err != nil || !ok {
		t.Fatalf("resolve on matching host = %v,%v", ok, err)
	}
	if string(got.Token) != "secret-token" || got.Username != "x-access-token" {
		t.Fatalf("resolved credential = %q/%q", got.Username, got.Token)
	}
	if _, ok, _ := resolver.ResolveGitCredential(context.Background(), "gitlab.com"); ok {
		t.Fatal("static resolver must not answer for a different host")
	}
}

func TestNewStaticCredentialResolverValidates(t *testing.T) {
	if _, err := NewStaticCredentialResolver("", "u", []byte("t")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty host error = %v, want validation", err)
	}
	if _, err := NewStaticCredentialResolver("github.com", "u", nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty token error = %v, want validation", err)
	}
}
