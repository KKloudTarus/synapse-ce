package ownadvisory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Alpine's own secdb is the authoritative apk advisory source, and it is materially richer than the OSV
// mirror of it for the branches people actually run: the OSV bulk feed carried 128 advisories keyed to
// Alpine:v3.19, and a scan of alpine:3.19 matched 4 CVEs against Trivy's 10 and Grype's 14. Until now secdb
// could only be ingested from a local directory an operator had already downloaded, which is a manual step
// nobody does, so the practical Alpine coverage was the thin one.
//
// This fetches it. Each branch publishes two small JSON files (main.json and community.json, tens of
// kilobytes), so the whole feed is a few hundred kilobytes rather than the hundreds of megabytes the OSV
// distro zips are.

const (
	defaultAlpineSecdbURL = "https://secdb.alpinelinux.org"
	// maxSecdbFileBytes bounds one secdb document. The largest current branch publishes about 130 KB, so this
	// is two orders of magnitude of headroom and still refuses a hostile endpoint streaming forever.
	maxSecdbFileBytes = 64 << 20
	// secdbBranchMin and secdbBranchMax bound the v3.<minor> branches probed. Probing a range rather than
	// carrying a list means a new Alpine release needs no code change, which is the drift a hardcoded list
	// guarantees; a branch that does not exist answers 404 and is skipped.
	secdbBranchMin = 10
	secdbBranchMax = 40
)

// secdbRepos are the package repositories each branch publishes.
var secdbRepos = []string{"main", "community"}

// RemoteSecdbFeed is an AdvisoryFeed over Alpine's published secdb. It walks every branch it can find and
// parses each repository's JSON with the same ParseSecdb the local directory feed uses, so the keying and the
// version comparator are identical either way.
type RemoteSecdbFeed struct {
	baseURL string
	client  *http.Client
}

var _ ports.AdvisoryFeed = (*RemoteSecdbFeed)(nil)

// NewRemoteSecdbFeed returns a feed over baseURL, defaulting to Alpine's published secdb. The client defaults
// to a bounded, redirect-refusing client over the same hardened transport the OSV bulk feed uses, so a
// redirect cannot bounce the fetch to another host and a name cannot resolve to a private address.
func NewRemoteSecdbFeed(baseURL string, client *http.Client) *RemoteSecdbFeed {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultAlpineSecdbURL
	}
	if client == nil {
		client = &http.Client{
			Timeout:       2 * time.Minute, // each document is tens of kilobytes
			CheckRedirect: noRedirect,
			Transport:     safeTransport(),
		}
	} else if client.CheckRedirect == nil {
		client.CheckRedirect = noRedirect
	}
	return &RemoteSecdbFeed{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

// Test performs one bounded metadata request against a branch that has existed for years, so a broken
// endpoint or a wrong URL fails before any ingest starts.
func (f *RemoteSecdbFeed) Test(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, f.baseURL+"/v3.19/main.json", nil)
	if err != nil {
		return fmt.Errorf("build secdb test: %w", err)
	}
	response, err := f.client.Do(request)
	if err != nil {
		return fmt.Errorf("secdb test request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("secdb test returned HTTP %d", response.StatusCode)
	}
	return nil
}

// Each fetches every branch's repositories and invokes fn for each advisory that resolved to a fixed package.
//
// A missing branch or repository is skipped, because Alpine publishes neither for every combination and a 404
// is the ordinary answer. A feed that yields NOTHING is fatal: an endpoint that answers every request with a
// 404 would otherwise look like a successful sync that ingested zero advisories, which is the silent gap this
// exists to close.
func (f *RemoteSecdbFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	skipped, documents := 0, 0
	// Aggregated across branches: an advisory that affects several of them must reach the store as ONE record
	// carrying every branch's fixed version, or the last branch read replaces the rest.
	agg := newSecdbAggregator()
	for minor := secdbBranchMin; minor <= secdbBranchMax; minor++ {
		for _, repo := range secdbRepos {
			if err := ctx.Err(); err != nil {
				return skipped, fmt.Errorf("secdb feed: %w", err)
			}
			branch := fmt.Sprintf("v3.%d", minor)
			body, found, err := f.fetch(ctx, branch, repo)
			if err != nil {
				return skipped, err
			}
			if !found {
				continue
			}
			documents++
			advisories, err := ParseSecdb(body)
			if err != nil {
				skipped++ // one unparseable document among many is a skip, never the whole sync
				continue
			}
			for _, adv := range advisories {
				if len(adv.Affected) == 0 {
					skipped++ // inert: resolved to no fixed package
					continue
				}
				if err := agg.add(adv); err != nil {
					return skipped, err
				}
			}
		}
	}
	if documents == 0 {
		return skipped, errors.New("secdb feed returned no documents: every branch answered 404, so the URL is wrong or the endpoint is not a secdb mirror")
	}
	if err := agg.each(fn); err != nil {
		return skipped, err
	}
	return skipped, nil
}

// fetch retrieves one branch's repository document. found is false for a 404, which is how a branch that does
// not publish that repository answers.
func (f *RemoteSecdbFeed) fetch(ctx context.Context, branch, repo string) ([]byte, bool, error) {
	// branch and repo are built from an integer range and a fixed list, so neither can carry a path segment.
	url := f.baseURL + "/" + branch + "/" + repo + ".json"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build secdb request: %w", err)
	}
	response, err := f.client.Do(request)
	if err != nil {
		return nil, false, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	switch {
	case response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone:
		return nil, false, nil
	case response.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("fetch %s: HTTP %d", url, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSecdbFileBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", url, err)
	}
	if int64(len(body)) > maxSecdbFileBytes {
		return nil, false, fmt.Errorf("%s exceeds the %d-byte cap", url, int64(maxSecdbFileBytes))
	}
	return body, true, nil
}
