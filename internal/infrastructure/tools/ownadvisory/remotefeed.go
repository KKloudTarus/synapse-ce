package ownadvisory

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// defaultOSVBulkURL is the public OSV bulk-data bucket. (Download/size caps live in limits.go.)
const defaultOSVBulkURL = "https://osv-vulnerabilities.storage.googleapis.com"

// noRedirect makes a client surface a 3xx as the response instead of following it – a redirect cannot bounce
// the fetch to an internal host (SSRF guard). Applied to the default client and to any injected client that
// has no redirect policy of its own.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// ecosystemRE bounds an OSV bucket ecosystem name to a safe single path segment (e.g. "Go", "npm",
// "crates.io") – no "/", no "..", so it cannot redirect the fetch to an unintended path. A name that fails
// is a configuration error (fatal), never silently skipped.
var ecosystemRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]*$`)

// defaultBulkEcosystems are the OSV bucket ecosystem directories the owned store covers (match osvEcosystem
// + the owned SBOM producer's ecosystems). Each is fetched as "<base>/<ecosystem>/all.zip".
var defaultBulkEcosystems = []string{"Go", "npm", "PyPI", "crates.io", "Maven", "RubyGems", "NuGet"}

// DistroBulkEcosystems are the OS-package ecosystems whose advisories the owned store can match (Epic B):
// the PURL→ecosystem bridge faithfully derives "Debian:<release>" and "Alpine:v<maj>.<min>", and the dpkg/
// apk comparators order their ranges. Each bare bucket dir aggregates ALL releases (records keep their
// release-versioned ecosystem, e.g. "Debian:10"). Kept SEPARATE from the default set: these zips are large,
// so they are fetched only on explicit operator request (sync-advisories --remote-distros).
var DistroBulkEcosystems = []string{"Debian", "Alpine"}

// RemoteFeed is an AdvisoryFeed that fetches OSV advisories from the OSV bulk-data bucket: per
// ecosystem it downloads "<base>/<ecosystem>/all.zip" and streams every advisory JSON inside into the store –
// the NO-TOUCH population path complementing the offline DirFeed. Safety: the ecosystem is validated to a
// single safe path segment (no SSRF/path redirect); the download is size-capped to a temp file (no unbounded
// memory or disk); each zip entry is read with a per-entry decompression cap (zip-bomb guard) and the entry
// count is bounded; entry names are never used as filesystem paths (no zip-slip – only the content is read).
// A per-ENTRY parse error is skipped+counted (best-effort, one bad advisory among thousands), while an
// HTTP/download/zip-open failure for a whole ecosystem is FATAL (a silently-skipped ecosystem would be a
// large hidden gap – fail loud so the operator re-runs).
type RemoteFeed struct {
	baseURL    string
	ecosystems []string
	client     *http.Client
}

// NewRemoteFeed returns a feed over the OSV bulk bucket. baseURL defaults to the public bucket; ecosystems
// defaults to the covered set; client defaults to a 10-minute, no-redirect client (the zips are large).
func NewRemoteFeed(baseURL string, ecosystems []string, client *http.Client) *RemoteFeed {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultOSVBulkURL
	}
	if len(ecosystems) == 0 {
		ecosystems = defaultBulkEcosystems
	}
	if client == nil {
		client = &http.Client{
			Timeout:       10 * time.Minute, // a per-ecosystem all.zip is large
			CheckRedirect: noRedirect,
		}
	} else if client.CheckRedirect == nil {
		client.CheckRedirect = noRedirect // defense-in-depth: a stock injected client must not follow redirects either
	}
	return &RemoteFeed{baseURL: strings.TrimRight(baseURL, "/"), ecosystems: ecosystems, client: client}
}

var _ ports.AdvisoryFeed = (*RemoteFeed)(nil)

// Each fetches every configured ecosystem's all.zip and streams its advisories to fn, returning the count of
// entries skipped (unparseable/oversized) and a fatal error (bad ecosystem name, HTTP/download/zip failure,
// ctx cancellation, or an error from fn).
func (f *RemoteFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	skipped := 0
	for _, eco := range f.ecosystems {
		if ctx.Err() != nil {
			return skipped, ctx.Err()
		}
		s, err := f.eachEcosystem(ctx, eco, fn)
		skipped += s
		if err != nil {
			return skipped, fmt.Errorf("ingest ecosystem %q: %w", eco, err)
		}
	}
	return skipped, nil
}

// eachEcosystem downloads one ecosystem's all.zip to a temp file and streams its advisories to fn.
func (f *RemoteFeed) eachEcosystem(ctx context.Context, eco string, fn func(a advisory.Advisory) error) (int, error) {
	if !ecosystemRE.MatchString(eco) {
		return 0, fmt.Errorf("%w: unsafe ecosystem name", shared.ErrValidation)
	}
	// eachEcosystem owns the temp file's WHOLE lifecycle (create → defer Close+Remove → fill via downloadInto);
	// downloadInto only writes into it, so there is no split create-here / clean-up-there ownership.
	tmp, err := os.CreateTemp("", "synapse-osv-*.zip")
	if err != nil {
		return 0, fmt.Errorf("temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()

	n, err := f.downloadInto(ctx, f.baseURL+"/"+eco+"/all.zip", tmp)
	if err != nil {
		return 0, err
	}
	zr, err := zip.NewReader(tmp, n)
	if err != nil {
		return 0, fmt.Errorf("open zip: %w", err)
	}
	skipped, entries := 0, 0
	for _, zf := range zr.File {
		if ctx.Err() != nil {
			return skipped, ctx.Err()
		}
		if zf.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(zf.Name), ".json") {
			continue
		}
		if entries++; entries > maxAdvisoryFiles {
			return skipped, fmt.Errorf("%w: zip exceeds %d entries; refusing to ingest", shared.ErrValidation, maxAdvisoryFiles)
		}
		adv, ok := readZipEntry(zf)
		if !ok {
			skipped++ // unreadable / oversized / unparseable advisory – best-effort, never aborts the sync
			continue
		}
		if err := fn(adv); err != nil {
			return skipped, err
		}
	}
	return skipped, nil
}

// readZipEntry decompresses one entry under the per-entry cap (zip-bomb guard) and parses it. ok=false on any
// read/oversize/parse failure (the caller skips+counts) – never a panic, never an unbounded read.
func readZipEntry(zf *zip.File) (advisory.Advisory, bool) {
	rc, err := zf.Open()
	if err != nil {
		return advisory.Advisory{}, false
	}
	defer func() { _ = rc.Close() }()
	// LimitReader to cap+1: a stream that fills the cap is treated as oversized (skipped), bounding memory to
	// one entry regardless of the entry's advertised uncompressed size.
	content, err := io.ReadAll(io.LimitReader(rc, maxAdvisoryBytes+1))
	if err != nil || int64(len(content)) > maxAdvisoryBytes {
		return advisory.Advisory{}, false
	}
	adv, err := ParseOSV(content)
	if err != nil {
		return advisory.Advisory{}, false
	}
	return adv, true
}

// downloadInto streams url into w under the download size cap and returns the bytes written. A non-2xx
// status, an over-cap body, or any I/O error is returned. It does not own w – the caller (eachEcosystem)
// creates and cleans up the temp file, so there is no cross-function file ownership.
func (f *RemoteFeed) downloadInto(ctx context.Context, url string, w io.Writer) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("%w: unexpected status %d", shared.ErrValidation, resp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxZipDownload+1))
	if err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}
	if n > maxZipDownload {
		return 0, fmt.Errorf("%w: zip exceeds %d-byte download cap", shared.ErrValidation, maxZipDownload)
	}
	return n, nil
}
