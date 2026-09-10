package ownadvisory

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilitysource"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// defaultGemnasiumURL is the GitLab Advisory Database (gemnasium-db) repository archive: one tar.gz holding
// every advisory as a per-package YAML file. GitLab advisories are NOT in the OSV mirror, so this is genuinely
// additional coverage (EPIC #860 D1.10). Download/entry caps live in limits.go.
const defaultGemnasiumURL = "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/archive/master/gemnasium-db-master.tar.gz"

// GitLabFeed is an AdvisoryFeed over the gemnasium-db repository archive. It downloads the tar.gz once
// (size-capped to a temp file, no unbounded memory or disk), then streams every "*.yml" advisory inside into
// the store, parsing each with ParseGemnasium. A per-ENTRY parse failure is skipped+counted (best-effort,
// one bad file among tens of thousands), while an HTTP/download/gzip/tar failure for the whole archive is
// FATAL (a silently-skipped archive would be a large hidden gap). Safety mirrors RemoteFeed: the SSRF-safe,
// no-redirect transport, the download cap, and the per-entry decompression cap (bomb guard); entry names are
// never used as filesystem paths (only the content is read).
type GitLabFeed struct {
	url    string
	client *http.Client
}

// NewGitLabFeed returns a feed over the gemnasium-db archive. url defaults to the public repository archive;
// client defaults to a 10-minute, no-redirect, SSRF-guarded client (the archive is tens of MB).
func NewGitLabFeed(url string, client *http.Client) *GitLabFeed {
	if strings.TrimSpace(url) == "" {
		url = defaultGemnasiumURL
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute, CheckRedirect: noRedirect, Transport: safeTransport()}
	} else if client.CheckRedirect == nil {
		client.CheckRedirect = noRedirect
	}
	return &GitLabFeed{url: strings.TrimSpace(url), client: client}
}

// Test performs one bounded metadata request and never downloads or parses the archive.
func (f *GitLabFeed) Test(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, f.url, nil)
	if err != nil {
		return fmt.Errorf("build gitlab feed test: %w", err)
	}
	response, err := f.client.Do(request)
	if err != nil {
		return fmt.Errorf("gitlab feed test request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("gitlab feed test returned HTTP %d", response.StatusCode)
	}
	return nil
}

// Each downloads the archive and yields every parseable advisory inside it.
func (f *GitLabFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	tmp, err := os.CreateTemp("", "synapse-gemnasium-*.tar.gz")
	if err != nil {
		return 0, fmt.Errorf("temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()

	if err := f.download(ctx, f.url, tmp); err != nil {
		return 0, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("rewind archive: %w", err)
	}
	gz, err := gzip.NewReader(tmp)
	if err != nil {
		return 0, fmt.Errorf("gunzip archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	skipped, entries := 0, 0
	// Cap the decompressed stream so a gzip bomb fails loudly rather than expanding without bound.
	tr := tar.NewReader(&cappedReader{r: gz, remaining: maxGemnasiumDecompressed})
	for {
		if ctx.Err() != nil {
			return skipped, ctx.Err()
		}
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return skipped, fmt.Errorf("read archive: %w", err) // gzip/tar corruption or the decompression cap: fatal
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		// Count EVERY regular entry (not only .yml) so a many-entry archive is bounded.
		if entries++; entries > maxAdvisoryFiles {
			return skipped, fmt.Errorf("%w: archive exceeds %d entries; refusing to ingest", shared.ErrValidation, maxAdvisoryFiles)
		}
		if !strings.HasSuffix(strings.ToLower(header.Name), ".yml") {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(tr, maxAdvisoryBytes+1))
		if err != nil {
			return skipped, fmt.Errorf("read archive entry %q: %w", header.Name, err) // archive corruption: fatal
		}
		if int64(len(content)) > maxAdvisoryBytes {
			skipped++ // a single oversized advisory: best-effort skip, never aborts the sync
			continue
		}
		adv, ok := ParseGemnasium(content)
		if !ok {
			skipped++
			continue
		}
		if err := fn(adv); err != nil {
			return skipped, err
		}
	}
	return skipped, nil
}

// cappedReader fails once total reads exceed remaining, so a decompressed stream that blows past a cap
// (a gzip bomb) surfaces as a read error rather than unbounded expansion.
type cappedReader struct {
	r         io.Reader
	remaining int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("%w: decompressed archive exceeds the %d-byte cap", shared.ErrValidation, maxGemnasiumDecompressed)
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// download streams url into w under the download size cap. A non-2xx status, an over-cap body, or any I/O
// error is returned. GitLab publishes no per-object checksum for the archive, so integrity here rides on TLS
// plus the SSRF-guarded, no-redirect transport.
func (f *GitLabFeed) download(ctx context.Context, url string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: unexpected status %d", shared.ErrValidation, resp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxZipDownload+1))
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if n > maxZipDownload {
		return fmt.Errorf("%w: archive exceeds %d-byte download cap", shared.ErrValidation, maxZipDownload)
	}
	return nil
}

// NewGitLabProvider wraps the gemnasium archive feed as a provider for a gitlab-typed source. It reuses the
// shared feed-provider pipeline (observations -> materializer), like the OSV remote provider.
func NewGitLabProvider(source vulnerabilitysource.Source) (*FeedProvider, error) {
	if source.AdapterType != vulnerabilitysource.AdapterGitLab {
		return nil, fmt.Errorf("%w: gitlab advisory provider does not support %q", shared.ErrValidation, source.AdapterType)
	}
	return NewFeedProvider(string(source.AdapterType), source.ID, NewGitLabFeed(source.Endpoint, nil))
}

var _ ports.AdvisoryFeed = (*GitLabFeed)(nil)
