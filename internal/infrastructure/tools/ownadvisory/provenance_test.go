package ownadvisory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// freshStore is a memStore that also reports corpus freshness (the postgres repo's optional capability).
type freshStore struct {
	memStore
	latest time.Time
	count  int
	err    error
}

func (f freshStore) AdvisoryFreshness(context.Context) (time.Time, int, error) {
	return f.latest, f.count, f.err
}

// TestProvenanceFreshnessMarker is D1.7: after a scan the owned source reports a "<count> advisories@<date>"
// corpus-freshness marker (so the SCA freshness policy can warn on a stale store and the report lists the
// feed's sync date). It is empty when the store cannot report freshness or the corpus is empty, so no false
// freshness is ever claimed.
func TestProvenanceFreshnessMarker(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "x", Version: "1.0.0", PURL: "pkg:npm/x@1.0.0"}}}

	// A store that reports freshness → a dated marker after Scan.
	fs := freshStore{latest: time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC), count: 4321}
	src := New(fs)
	if _, err := src.Scan(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	ver, db := src.Provenance()
	if ver != "" {
		t.Errorf("owned source has no tool version, got %q", ver)
	}
	if db != "4321 advisories@2026-01-15" {
		t.Errorf("freshness marker = %q, want %q", db, "4321 advisories@2026-01-15")
	}

	// An empty corpus → no marker (never a false freshness claim).
	empty := New(freshStore{latest: time.Time{}, count: 0})
	if _, err := empty.Scan(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	if _, db := empty.Provenance(); db != "" {
		t.Errorf("empty corpus must have no marker, got %q", db)
	}

	// A store without the freshness capability → no marker (memStore alone).
	plain := New(memStore{})
	if _, err := plain.Scan(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	if _, db := plain.Provenance(); db != "" {
		t.Errorf("a store without freshness must have no marker, got %q", db)
	}
}
