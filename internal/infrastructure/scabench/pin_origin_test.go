package scabench

import (
	"strings"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// TestRequirePinNamesOriginOnDigestDrift pins the diagnostic contract. A digest mismatch on a pinned
// database is far more often an upstream republishing its feed in place than a locally corrupted copy,
// so the failure must say which upstream to re-fetch. Without the origin an operator only learns that
// "the database changed" and has to rediscover which of several feeds moved.
func TestRequirePinNamesOriginOnDigestDrift(t *testing.T) {
	const (
		reference = "database:owned:sles-15-sp6-affected-oval-2026-09-20"
		origin    = "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.15-sp6-affected.xml.gz"
		pinned    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		verified  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	catalog := bench.Catalog{Pins: []bench.ArtifactPin{{Reference: reference, Digest: pinned, Origin: origin}}}

	err := requirePin(catalog, reference, verified, "database")
	if err == nil {
		t.Fatal("a digest mismatch must fail the capture")
	}
	for _, want := range []string{origin, pinned, verified} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("drift error must contain %q, got %v", want, err)
		}
	}

	// A matching digest still passes, so the added diagnostics cannot turn a good pin into a failure.
	if err := requirePin(catalog, reference, pinned, "database"); err != nil {
		t.Fatalf("a matching digest must pass: %v", err)
	}
}

// TestRequirePinWithoutOriginStillReportsBothDigests keeps locally built artifacts diagnosable even
// though they carry no upstream to re-fetch.
func TestRequirePinWithoutOriginStillReportsBothDigests(t *testing.T) {
	const (
		reference = "binary:synapse-sca-bench:reproducible-v1"
		pinned    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		verified  = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	)
	catalog := bench.Catalog{Pins: []bench.ArtifactPin{{Reference: reference, Digest: pinned}}}
	err := requirePin(catalog, reference, verified, "binary")
	if err == nil {
		t.Fatal("a digest mismatch must fail the capture")
	}
	if !strings.Contains(err.Error(), pinned) || !strings.Contains(err.Error(), verified) {
		t.Fatalf("error must report both digests, got %v", err)
	}
	if strings.Contains(err.Error(), "re-fetch") {
		t.Fatalf("an origin-less pin must not advise re-fetching, got %v", err)
	}
}

// TestRequirePinRejectsMissingPin keeps a capture from proceeding against an unpinned artifact.
func TestRequirePinRejectsMissingPin(t *testing.T) {
	catalog := bench.Catalog{Pins: []bench.ArtifactPin{{
		Reference: "database:grype:other",
		Digest:    "sha256:5555555555555555555555555555555555555555555555555555555555555555",
	}}}
	err := requirePin(catalog, "database:grype:absent", "sha256:5555555555555555555555555555555555555555555555555555555555555555", "database")
	if err == nil || !strings.Contains(err.Error(), "is required") {
		t.Fatalf("an unpinned artifact must be rejected, got %v", err)
	}
}
