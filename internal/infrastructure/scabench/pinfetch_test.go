package scabench

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// stubFetcher serves canned bytes per origin so archive behavior is testable without network access.
type stubFetcher struct {
	bodies map[string][]byte
	errs   map[string]error
	calls  []string
}

func (f *stubFetcher) Fetch(_ context.Context, origin string) ([]byte, error) {
	f.calls = append(f.calls, origin)
	if err, exists := f.errs[origin]; exists {
		return nil, err
	}
	body, exists := f.bodies[origin]
	if !exists {
		return nil, errors.New("no canned body")
	}
	return body, nil
}

var _ PinFetcher = (*stubFetcher)(nil)

func fixedTime(t *testing.T) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, "2026-09-22T00:00:00Z")
	if err != nil {
		t.Fatalf("parse fixed time: %v", err)
	}
	return at
}

// TestArchiveCatalogPinsRetainsMatchingBytes covers the ordinary path: a pin whose origin still
// serves the pinned bytes is archived and the manifest passes coverage.
func TestArchiveCatalogPinsRetainsMatchingBytes(t *testing.T) {
	oval := []byte("<oval>suse definitions</oval>")
	vex := []byte(`{"document":{"tracking":{"version":"2"}}}`)
	catalog := bench.Catalog{Revision: "rev-1", Pins: []bench.ArtifactPin{
		{Reference: "database:owned:sles", Digest: bench.SHA256Digest(oval), Origin: "https://ftp.suse.com/oval.xml.gz"},
		{Reference: "source:redhat-vex", Digest: bench.SHA256Digest(vex), Origin: "https://security.access.redhat.com/vex.json"},
		{Reference: "binary:synapse-sca-bench:reproducible-v1", Digest: bench.SHA256Digest([]byte("local"))},
	}}
	fetcher := &stubFetcher{bodies: map[string][]byte{
		"https://ftp.suse.com/oval.xml.gz":            oval,
		"https://security.access.redhat.com/vex.json": vex,
	}}
	store := newStore(t)

	result, err := ArchiveCatalogPins(context.Background(), catalog, fetcher, store, fixedTime(t))
	if err != nil {
		t.Fatalf("archive catalog pins: %v", err)
	}
	if len(result.Drifted) != 0 || len(result.Failed) != 0 {
		t.Fatalf("no pin should drift or fail, got drifted=%+v failed=%+v", result.Drifted, result.Failed)
	}
	if len(result.Archive.Entries) != 2 {
		t.Fatalf("both fetchable pins must be archived, got %d", len(result.Archive.Entries))
	}
	// The origin-less pin is produced locally, so it must never be fetched.
	for _, origin := range fetcher.calls {
		if origin == "" {
			t.Fatal("an origin-less pin must not be fetched")
		}
	}
	if err := bench.ValidateArchiveCoverage(catalog, result.Archive); err != nil {
		t.Fatalf("a complete run must satisfy coverage: %v", err)
	}
	if err := VerifyArchive(store, result.Archive); err != nil {
		t.Fatalf("archived bytes must verify: %v", err)
	}
	// Capture time is recorded in UTC so two archives of the same bytes order identically.
	if got := result.Archive.Entries[0].CapturedAt; got != "2026-09-22T00:00:00Z" {
		t.Fatalf("capture time must be the supplied UTC instant, got %q", got)
	}
}

// TestArchiveCatalogPinsReportsDriftWithoutRetainingIt is the central behavior for a corpus pinned
// before archival existed. Drift must be reported per pin, must not be stored under the pin it does
// not match, and must not prevent the still-retrievable pins from being archived.
func TestArchiveCatalogPinsReportsDriftWithoutRetainingIt(t *testing.T) {
	good := []byte("still the pinned bytes")
	regenerated := []byte("the vendor regenerated this document")
	pinnedButGone := bench.SHA256Digest([]byte("the bytes that were originally pinned"))
	catalog := bench.Catalog{Revision: "rev-1", Pins: []bench.ArtifactPin{
		{Reference: "database:owned:debian", Digest: bench.SHA256Digest(good), Origin: "https://debian.org/oval.xml.bz2"},
		{Reference: "source:redhat-vex-cve-2026-22185", Digest: pinnedButGone, Origin: "https://security.access.redhat.com/vex.json"},
	}}
	fetcher := &stubFetcher{bodies: map[string][]byte{
		"https://debian.org/oval.xml.bz2":             good,
		"https://security.access.redhat.com/vex.json": regenerated,
	}}
	store := newStore(t)

	result, err := ArchiveCatalogPins(context.Background(), catalog, fetcher, store, fixedTime(t))
	if err != nil {
		t.Fatalf("drift must not fail the run: %v", err)
	}
	if len(result.Archive.Entries) != 1 || result.Archive.Entries[0].Reference != "database:owned:debian" {
		t.Fatalf("the retrievable pin must still be archived, got %+v", result.Archive.Entries)
	}
	if len(result.Drifted) != 1 {
		t.Fatalf("the regenerated pin must be reported as drifted, got %+v", result.Drifted)
	}
	drift := result.Drifted[0]
	if drift.Pinned != pinnedButGone || drift.Served != bench.SHA256Digest(regenerated) {
		t.Fatalf("drift must report both digests, got pinned=%s served=%s", drift.Pinned, drift.Served)
	}
	if drift.Origin == "" {
		t.Fatal("drift must name the origin to re-fetch")
	}
	// Nothing may be retained under the pinned digest, or a later capture would verify against bytes
	// the oracle's citations do not describe.
	if _, err := store.Get(pinnedButGone); err == nil {
		t.Fatal("drifted bytes must not be retained under the pinned digest")
	}
	// Coverage must still fail, because the corpus is not fully reproducible.
	err = bench.ValidateArchiveCoverage(catalog, result.Archive)
	if err == nil || !strings.Contains(err.Error(), "source:redhat-vex-cve-2026-22185") {
		t.Fatalf("coverage must name the unarchivable pin, got %v", err)
	}
}

// TestArchiveCatalogPinsReportsFetchFailureSeparately keeps an unreachable origin distinguishable
// from a drifted one, because they call for different operator responses.
func TestArchiveCatalogPinsReportsFetchFailureSeparately(t *testing.T) {
	catalog := bench.Catalog{Revision: "rev-1", Pins: []bench.ArtifactPin{
		{Reference: "database:grype:v6", Digest: bench.SHA256Digest([]byte("db")), Origin: "https://grype.anchore.io/db.tar.zst"},
	}}
	fetcher := &stubFetcher{errs: map[string]error{
		"https://grype.anchore.io/db.tar.zst": errors.New("pin origin returned status 404"),
	}}

	result, err := ArchiveCatalogPins(context.Background(), catalog, fetcher, newStore(t), fixedTime(t))
	if err != nil {
		t.Fatalf("a fetch failure must not fail the run: %v", err)
	}
	if len(result.Drifted) != 0 {
		t.Fatalf("an unreachable origin is not drift, got %+v", result.Drifted)
	}
	if len(result.Failed) != 1 || !strings.Contains(result.Failed[0].Reason, "404") {
		t.Fatalf("the failure must be reported with its reason, got %+v", result.Failed)
	}
}

// TestArchiveCatalogPinsRequiresItsDependencies keeps a missing collaborator from reading as a clean
// empty archive.
func TestArchiveCatalogPinsRequiresItsDependencies(t *testing.T) {
	catalog := bench.Catalog{Revision: "rev-1"}
	if _, err := ArchiveCatalogPins(context.Background(), catalog, nil, newStore(t), fixedTime(t)); err == nil {
		t.Error("a nil fetcher must be rejected")
	}
	if _, err := ArchiveCatalogPins(context.Background(), catalog, &stubFetcher{}, nil, fixedTime(t)); err == nil {
		t.Error("a nil store must be rejected")
	}
	if _, err := ArchiveCatalogPins(context.Background(), bench.Catalog{}, &stubFetcher{}, newStore(t), fixedTime(t)); err == nil {
		t.Error("a catalog without a revision must be rejected")
	}
}

// TestArchiveCatalogPinsHonoursCancellation keeps a long archive run interruptible.
func TestArchiveCatalogPinsHonoursCancellation(t *testing.T) {
	body := []byte("feed")
	catalog := bench.Catalog{Revision: "rev-1", Pins: []bench.ArtifactPin{
		{Reference: "database:owned:a", Digest: bench.SHA256Digest(body), Origin: "https://example.org/a"},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ArchiveCatalogPins(ctx, catalog, &stubFetcher{bodies: map[string][]byte{"https://example.org/a": body}}, newStore(t), fixedTime(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context must stop the run, got %v", err)
	}
}

// TestValidatePinOriginRefusesUnsafeOrigins pins the transport contract.
//
// It asserts the specific reason each origin is refused rather than merely that Fetch errors. Going
// through Fetch would dial the network, and an unreachable host produces an error too — so a removed
// scheme or credential check would still leave the test green for the wrong reason.
func TestValidatePinOriginRefusesUnsafeOrigins(t *testing.T) {
	cases := []struct {
		origin  string
		wantErr string
	}{
		{"http://security.access.redhat.com/vex.json", "must use https"},
		{"ftp://ftp.suse.com/oval.xml.gz", "must use https"},
		{"file:///etc/passwd", "must use https"},
		{"oci://ghcr.io/aquasecurity/trivy-db:2", "must use https"},
		{"", "must use https"},
		{"https:///feed.json", "has no host"},
		{"https://user:secret@example.org/feed.json", "must not carry credentials"},
	}
	for _, testCase := range cases {
		err := validatePinOrigin(testCase.origin)
		if err == nil {
			t.Errorf("origin %q must be refused", testCase.origin)
			continue
		}
		if !strings.Contains(err.Error(), testCase.wantErr) {
			t.Errorf("origin %q must be refused for %q, got %v", testCase.origin, testCase.wantErr, err)
		}
	}

	// An ordinary vendor feed must still be accepted, so the guard cannot pass by refusing everything.
	if err := validatePinOrigin("https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-22185.json"); err != nil {
		t.Fatalf("a plain https origin must be accepted: %v", err)
	}
}

// TestValidatePinOriginRedactsCredentials keeps a secret embedded in a corpus origin out of the error
// text, which reaches logs and archive run output.
func TestValidatePinOriginRedactsCredentials(t *testing.T) {
	err := validatePinOrigin("https://operator:s3cr3t-token@example.org/feed.json")
	if err == nil {
		t.Fatal("a credential-bearing origin must be refused")
	}
	if strings.Contains(err.Error(), "s3cr3t-token") {
		t.Fatalf("the error must not echo the credential, got %v", err)
	}
}
