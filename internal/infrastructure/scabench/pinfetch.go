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

// NewHTTPPinFetcher builds a fetcher that refuses private and link-local destinations.
func NewHTTPPinFetcher() *HTTPPinFetcher {
	return &HTTPPinFetcher{client: safehttp.New(pinFetchTimeout, false)}
}

// Fetch retrieves an origin's bytes.
//
// Only HTTPS is accepted. A pin origin is attacker-influencing input in the sense that it is data in
// a corpus file rather than a compiled constant, so plaintext or a non-HTTP scheme is refused instead
// of being attempted — an archived artifact fetched over a tamperable channel would be evidence of
// nothing. Redirects are not followed, because the shared client returns the redirect response and a
// pin must name the location its bytes actually came from.
func (f *HTTPPinFetcher) Fetch(ctx context.Context, origin string) ([]byte, error) {
	if err := validatePinOrigin(origin); err != nil {
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

// validatePinOrigin refuses an origin that could not yield trustworthy evidence.
//
// This is separate from Fetch so the rule is decidable without a network dial. Asserting it through
// Fetch would let a rejected origin and an origin that merely failed to resolve produce the same
// observable outcome, which is how a missing check passes a test that only expects "some error".
func validatePinOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("parse pin origin: %w", err)
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
	// Drifted names pins whose origin now serves different bytes. This is the expected outcome for a
	// corpus pinned before archiving existed, and it is reported separately from Failed because it is
	// a finding about the vendor rather than an error in the run.
	Drifted []DriftedPin
	// Failed names pins that could not be retrieved at all.
	Failed []FailedPin
}

// DriftedPin records an origin that no longer serves its pinned bytes.
type DriftedPin struct {
	Reference string
	Origin    string
	Pinned    string
	Served    string
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
			result.Failed = append(result.Failed, FailedPin{Reference: pin.Reference, Origin: pin.Origin, Reason: err.Error()})
			continue
		}
		if err := store.Put(pin.Digest, data); err != nil {
			served := bench.SHA256Digest(data)
			if served != pin.Digest {
				result.Drifted = append(result.Drifted, DriftedPin{
					Reference: pin.Reference, Origin: pin.Origin, Pinned: pin.Digest, Served: served,
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
