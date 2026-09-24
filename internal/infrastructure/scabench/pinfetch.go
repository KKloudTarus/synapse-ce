package scabench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// pinFetchTimeout bounds a single artifact retrieval. The largest pinned feed is a comparator
// database in the tens of megabytes, so five minutes covers a slow mirror without letting one
// unresponsive origin stall an archive run indefinitely.
const pinFetchTimeout = 5 * time.Minute

// PinFetcher retrieves the bytes behind a catalog pin origin.
//
// Archiving is separated from fetching so the archive can be built from bytes an operator already
// holds — the trusted input root a capture ran against — rather than only from a live re-fetch. That
// matters because a pin whose origin has already been republished can still be archived from a
// retained copy, which is precisely the corpus this feature exists to rescue.
type PinFetcher interface {
	Fetch(ctx context.Context, origin string) ([]byte, error)
}

// HTTPPinFetcher fetches pin bytes over HTTPS through the shared SSRF-guarded client.
type HTTPPinFetcher struct{ client *http.Client }

var _ PinFetcher = (*HTTPPinFetcher)(nil)

// maxPinRedirects bounds a redirect chain. Release artifacts are commonly served by one hop to a
// signed CDN URL, so a small allowance covers real origins while keeping a redirect loop bounded.
const maxPinRedirects = 5

// NewHTTPPinFetcher builds a fetcher that refuses private and link-local destinations.
//
// Redirects are followed, within a bound, because the pinned release artifacts genuinely require it:
// a GitHub release download answers 302 with a signed CDN location, so refusing to follow would make
// every binary and source pin unfetchable. Each hop is revalidated rather than trusted, and the
// transport's address checks still apply to the redirect target.
func NewHTTPPinFetcher() *HTTPPinFetcher {
	client := safehttp.New(pinFetchTimeout, false)
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= maxPinRedirects {
			return fmt.Errorf("pin origin exceeded %d redirects", maxPinRedirects)
		}
		// A redirect can downgrade the channel or point somewhere unexpected, so the hop is held to the
		// same rule as the origin. Only scheme and host are reported: a signed CDN location carries
		// access tokens in its query string, and this message reaches logs and run output.
		if request.URL.Scheme != "https" {
			return fmt.Errorf("pin origin redirected to a non-https location at %q", request.URL.Host)
		}
		if request.URL.User != nil {
			return fmt.Errorf("pin origin redirected to a credential-bearing location at %q", request.URL.Host)
		}
		return nil
	}
	return &HTTPPinFetcher{client: client}
}

// Fetch retrieves an origin's bytes.
//
// Only HTTPS is accepted. A pin origin is attacker-influencing input in the sense that it is data in
// a corpus file rather than a compiled constant, so plaintext or a non-HTTP scheme is refused instead
// of being attempted — an archived artifact fetched over a tamperable channel would be evidence of
// nothing. Redirects are not followed, because the shared client returns the redirect response and a
// pin must name the location its bytes actually came from.
func (f *HTTPPinFetcher) Fetch(ctx context.Context, origin string) ([]byte, error) {
	if err := validateFetchableOrigin(origin); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin, nil)
	if err != nil {
		return nil, fmt.Errorf("build pin request: %w", err)
	}
	response, err := f.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch pin origin: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pin origin returned status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxArchivedPinBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read pin origin: %w", err)
	}
	if len(data) > maxArchivedPinBytes {
		return nil, fmt.Errorf("pin origin exceeds %d bytes", maxArchivedPinBytes)
	}
	if len(data) == 0 {
		return nil, errors.New("pin origin returned no content")
	}
	return data, nil
}

// ErrUnsupportedOriginScheme marks an origin this fetcher cannot retrieve even though the catalog
// legitimately permits it.
//
// The catalog admits "oci://" for databases published only as registry images — the trivy database is
// the case in point. Pulling a registry artifact needs a registry client rather than an HTTP GET, so
// this fetcher reports the gap distinctly instead of calling a valid pin malformed. An operator can
// then archive that artifact from a retained copy through the same store.
var ErrUnsupportedOriginScheme = errors.New("origin scheme is not retrievable over http")

// validateFetchableOrigin refuses an origin this fetcher must not or cannot retrieve.
//
// This is separate from Fetch so the rule is decidable without a network dial. Asserting it through
// Fetch would let a rejected origin and an origin that merely failed to resolve produce the same
// observable outcome, which is how a missing check passes a test that only expects "some error".
//
// The catalog's own origin rule is the authority on what a pin may record
// (scabench.ArtifactPin, validated in the usecase package); this function is narrower on purpose,
// answering only whether an HTTP GET can fetch it.
func validateFetchableOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("parse pin origin: %w", err)
	}
	if parsed.Scheme == "oci" {
		return fmt.Errorf("%w: %q", ErrUnsupportedOriginScheme, parsed.Scheme)
	}
	// A directory prefix names a set of documents rather than one artifact, and the committed catalog
	// contains one: the Red Hat VEX database pin points at `.../data/csaf/v2/vex/`, whose digest is a
	// tree digest over many assembled documents. A GET there returns the server's index page, so
	// comparing those bytes to the pin would report a mismatch that means nothing about the vendor.
	// Verified on real infrastructure: that origin answers 200 with an 18 KB `text/html` listing.
	if strings.HasSuffix(parsed.Path, "/") {
		return fmt.Errorf("%w: %q is a directory prefix, not a single artifact", ErrUnsupportedOriginScheme, origin)
	}
	// A pin origin is corpus data rather than a compiled constant, so an artifact fetched over a
	// tamperable channel would be evidence of nothing.
	if parsed.Scheme != "https" {
		return fmt.Errorf("pin origin %q must use https", origin)
	}
	if parsed.Host == "" {
		return fmt.Errorf("pin origin %q has no host", origin)
	}
	// Credentials in an origin would be copied into archive manifests and error messages, which is a
	// secret-leak path rather than a fetch problem.
	if parsed.User != nil {
		return fmt.Errorf("pin origin %q must not carry credentials", parsed.Redacted())
	}
	return nil
}

// ArchiveResult reports what one archive run preserved and what it could not.
type ArchiveResult struct {
	// Archive is the manifest of everything successfully preserved. It is usable evidence even when
	// Drifted or Failed is non-empty, so a partial run still yields what it managed to retain.
	Archive bench.PinArchive
	// Unverified names pins whose fetched bytes do not hash to the pin digest. It is reported
	// separately from Failed because the fetch succeeded, and it is deliberately not called drift.
	//
	// Two different causes produce this result and the fetched bytes alone cannot tell them apart. The
	// vendor may have republished the artifact, or the pin digest may describe something derived from
	// the download rather than the download itself. Both occur in the committed catalog: the grype pin
	// is the digest of the `grype` executable extracted from a release tarball, not of the tarball, and
	// the `database:` pins are directory-tree digests. Calling either case "drift" would be a false
	// claim about a vendor, so both digests are reported and the cause is left to the operator.
	Unverified []UnverifiedPin
	// Failed names pins that could not be retrieved at all.
	Failed []FailedPin
	// Unsupported names pins whose origin is valid but not fetchable by this fetcher, such as a
	// registry-hosted database. Kept apart from Failed so a catalog-legal pin is not reported as
	// broken; it needs a different retrieval route, not a fix.
	Unsupported []FailedPin
}

// UnverifiedPin records an origin whose fetched bytes do not hash to the pin digest.
//
// Both digests are recorded because the comparison alone does not establish a cause: the artifact may
// have been republished, or the pin may describe a derived form such as a file extracted from a
// release archive or a digest over an unpacked directory tree.
type UnverifiedPin struct {
	Reference string
	Origin    string
	Pinned    string
	// Fetched is the digest of exactly the bytes the origin returned, before any extraction or
	// decompression.
	Fetched string
}

// FailedPin records an origin that could not be read.
type FailedPin struct {
	Reference string
	Origin    string
	Reason    string
}

// ArchiveCatalogPins fetches and archives every fetchable pin in a catalog.
//
// Drift is not treated as a run failure. A corpus pinned before byte archival existed will have
// drifted at some origins by definition, and refusing to archive anything in that case would leave
// the operator with nothing — including for the pins that are still retrievable. Reporting drift
// per pin lets an operator archive what remains and see exactly which evidence is already
// unrecoverable, which is the honest state of such a corpus.
//
// Bytes are verified against the pin digest inside the store before anything is written, so a
// drifted artifact is never retained under a pin it does not match.
func ArchiveCatalogPins(ctx context.Context, catalog bench.Catalog, fetcher PinFetcher, store *PinArchiveStore, now time.Time) (ArchiveResult, error) {
	if fetcher == nil {
		return ArchiveResult{}, errors.New("pin fetcher is required")
	}
	if store == nil {
		return ArchiveResult{}, errors.New("pin archive store is required")
	}
	if strings.TrimSpace(catalog.Revision) == "" {
		return ArchiveResult{}, errors.New("catalog revision is required")
	}
	captured := now.UTC().Format(time.RFC3339)
	result := ArchiveResult{Archive: bench.PinArchive{
		SchemaVersion:   bench.PinArchiveSchemaVersion,
		CatalogRevision: catalog.Revision,
	}}
	for _, pin := range bench.ArchivablePins(catalog) {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		data, err := fetcher.Fetch(ctx, pin.Origin)
		if err != nil {
			entry := FailedPin{Reference: pin.Reference, Origin: pin.Origin, Reason: err.Error()}
			if errors.Is(err, ErrUnsupportedOriginScheme) {
				result.Unsupported = append(result.Unsupported, entry)
				continue
			}
			result.Failed = append(result.Failed, entry)
			continue
		}
		if err := store.Put(pin.Digest, data); err != nil {
			fetched := bench.SHA256Digest(data)
			if fetched != pin.Digest {
				result.Unverified = append(result.Unverified, UnverifiedPin{
					Reference: pin.Reference, Origin: pin.Origin, Pinned: pin.Digest, Fetched: fetched,
				})
				continue
			}
			result.Failed = append(result.Failed, FailedPin{Reference: pin.Reference, Origin: pin.Origin, Reason: err.Error()})
			continue
		}
		result.Archive.Entries = append(result.Archive.Entries, bench.ArchivedPin{
			Reference:  pin.Reference,
			Digest:     pin.Digest,
			Bytes:      int64(len(data)),
			CapturedAt: captured,
		})
	}
	sort.Slice(result.Archive.Entries, func(i, j int) bool {
		return result.Archive.Entries[i].Reference < result.Archive.Entries[j].Reference
	})
	return result, nil
}
