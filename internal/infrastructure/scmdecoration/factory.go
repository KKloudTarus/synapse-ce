package scmdecoration

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ForProvider builds the owned PR decorator for a forge provider. The provider string is the CI
// context's `Provider` claim (for example "github-actions", "gitlab-ci", "bitbucket-pipelines") or a
// bare forge name ("github"/"gitlab"/"bitbucket"); the concrete cloud host is chosen by the adapter.
// An unsupported provider is a validation error so the caller can skip decoration rather than guess.
func ForProvider(provider string, credentials ports.GitCredentialResolver) (ports.PRDecorator, error) {
	switch normalizeProvider(provider) {
	case "github":
		return NewGitHubDecorator(credentials)
	case "gitlab":
		return NewGitLabDecorator(credentials)
	case "bitbucket":
		return NewBitbucketDecorator(credentials)
	default:
		return nil, fmt.Errorf("%w: unsupported decoration provider %q (want one of %s)", shared.ErrValidation, provider, strings.Join(SupportedProviders(), ", "))
	}
}

// SupportedProviders lists the decoration provider tokens ForProvider accepts, for CLI help and errors.
func SupportedProviders() []string {
	return []string{"github", "gitlab", "bitbucket"}
}

// CredentialHostForProvider returns the forge host a decoration credential must answer for, so a caller
// can scope a supplied token to the expected host instead of offering it to any resolver query.
func CredentialHostForProvider(provider string) (string, bool) {
	switch normalizeProvider(provider) {
	case "github":
		return githubCredentialHost, true
	case "gitlab":
		return gitlabCredentialHost, true
	case "bitbucket":
		return bitbucketCredentialHost, true
	default:
		return "", false
	}
}

// normalizeProvider folds a CI provider claim to one of github/gitlab/bitbucket. It matches on a prefix
// so "github", "github-actions", and "github-enterprise" all resolve to github, and returns the input
// lowercased when it matches nothing so the caller reports the unsupported value verbatim.
func normalizeProvider(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch {
	case strings.HasPrefix(p, "github"):
		return "github"
	case strings.HasPrefix(p, "gitlab"):
		return "gitlab"
	case strings.HasPrefix(p, "bitbucket"):
		return "bitbucket"
	default:
		return p
	}
}

// staticCredentialResolver answers one forge host with one supplied credential. It exists for the CLI,
// where the decoration token is provided by the CI environment rather than the server-side vault; the
// token is scoped to the expected host so it is never offered for a different host's query.
type staticCredentialResolver struct {
	host     string
	username string
	token    []byte
}

// NewStaticCredentialResolver builds a single-host credential resolver from a CI-provided token. The
// token is copied; callers should still treat the source as sensitive. An empty host or token is a
// validation error because a decorator would otherwise resolve nothing and fail every write.
func NewStaticCredentialResolver(host, username string, token []byte) (ports.GitCredentialResolver, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return nil, fmt.Errorf("%w: decoration credential host is required", shared.ErrValidation)
	}
	if len(token) == 0 {
		return nil, fmt.Errorf("%w: decoration credential token is required", shared.ErrValidation)
	}
	return &staticCredentialResolver{host: host, username: strings.TrimSpace(username), token: append([]byte(nil), token...)}, nil
}

func (r *staticCredentialResolver) ResolveGitCredential(_ context.Context, host string) (ports.GitCredential, bool, error) {
	if !strings.EqualFold(strings.TrimSpace(host), r.host) {
		return ports.GitCredential{}, false, nil
	}
	return ports.GitCredential{Username: r.username, Token: append([]byte(nil), r.token...)}, true, nil
}
