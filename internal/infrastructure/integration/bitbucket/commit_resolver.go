package bitbucket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var repositorySegment = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var commitHash = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
var commitPrefix = regexp.MustCompile(`^[a-fA-F0-9]{12}$`)

type CommitResolver struct {
	client      *http.Client
	credentials ports.GitCredentialResolver
}

var _ ports.BitbucketCommitResolver = (*CommitResolver)(nil)

func NewCommitResolver(credentials ports.GitCredentialResolver) (*CommitResolver, error) {
	if credentials == nil {
		return nil, fmt.Errorf("%w: Bitbucket commit credential resolver is required", shared.ErrValidation)
	}
	return &CommitResolver{client: safehttp.New(5*time.Second, false), credentials: credentials}, nil
}

func (r *CommitResolver) ResolveBitbucketCommit(ctx context.Context, repository, prefix string, disableCredentials bool) (string, error) {
	path, err := repositoryPath(repository)
	if err != nil || !commitPrefix.MatchString(prefix) {
		return "", fmt.Errorf("%w: invalid Bitbucket commit lookup", shared.ErrValidation)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.bitbucket.org/2.0/repositories/"+path+"/commit/"+strings.ToLower(prefix)+"?fields=hash", nil)
	if err != nil {
		return "", fmt.Errorf("build Bitbucket commit lookup: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if !disableCredentials {
		credential, found, err := r.credentials.ResolveGitCredential(ctx, "bitbucket.org")
		if err != nil {
			return "", fmt.Errorf("bitbucket commit credential lookup failed")
		}
		defer func() { clear(credential.Token) }()
		if found {
			username := credential.Username
			if username == "" {
				username = "x-token-auth"
			}
			req.SetBasicAuth(username, string(credential.Token))
		}
	}
	resp, err := r.client.Do(req)
	if err != nil {
		// Transport and response bodies may contain credentials or user data.
		return "", fmt.Errorf("bitbucket commit lookup failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bitbucket commit lookup returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(body) > 4096 {
		return "", fmt.Errorf("bitbucket commit response could not be read within its limit")
	}
	var result struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(body, &result); err != nil || !commitHash.MatchString(result.Hash) || !strings.HasPrefix(strings.ToLower(result.Hash), strings.ToLower(prefix)) {
		return "", fmt.Errorf("%w: Bitbucket commit response does not match the requested prefix", shared.ErrValidation)
	}
	return strings.ToLower(result.Hash), nil
}

func repositoryPath(repository string) (string, error) {
	u, err := url.Parse(repository)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "bitbucket.org") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", fmt.Errorf("%w: Bitbucket Cloud source is required", shared.ErrValidation)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("%w: Bitbucket repository path is invalid", shared.ErrValidation)
	}
	parts[1] = strings.TrimSuffix(parts[1], ".git")
	for _, part := range parts {
		if !repositorySegment.MatchString(part) || part == "." || part == ".." {
			return "", fmt.Errorf("%w: Bitbucket repository path is invalid", shared.ErrValidation)
		}
	}
	return parts[0] + "/" + parts[1], nil
}
