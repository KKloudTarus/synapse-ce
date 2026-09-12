package sca

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestOwnedOnlyScanNeedsNoSyftOrGrype is the owned-only end-to-end gate for EPIC #860's "run without Syft or
// Grype" goal. It wires the REAL owned SBOM producer (ownsbom parsers) and the REAL owned detection source
// (ownadvisory over a populated store) as the ONLY sources — no Syft generator, no Grype scanner anywhere —
// and proves a full scan still produces a vulnerability finding from a lockfile. This is the regression proof
// that the owned engine is self-sufficient: if either owned half regresses, the finding disappears here.
func TestOwnedOnlyScanNeedsNoSyftOrGrype(t *testing.T) {
	// Fixture: a repo whose npm lockfile pins a vulnerable lodash (4.17.0 < the 4.17.12 fix).
	dir := t.TempDir()
	lock := `{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"lodash": "^4"}},
    "node_modules/lodash": {"version": "4.17.0"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	// Owned advisory corpus: one real npm advisory (CVE-2019-10744, lodash < 4.17.12).
	store := memory.NewAdvisoryStore()
	if err := store.Upsert(context.Background(), advisory.Advisory{
		ID:       "CVE-2019-10744",
		Summary:  "Prototype pollution in lodash",
		Severity: shared.SeverityCritical,
		Affected: []advisory.AffectedPackage{{
			Ecosystem:    "npm",
			Package:      "lodash",
			Ranges:       []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "4.17.12"}}}},
			FixedVersion: "4.17.12",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	reg, err := ownsbom.DefaultRegistry()
	if err != nil {
		t.Fatalf("owned sbom registry: %v", err)
	}

	// The ONLY detection source is the owned advisory matcher. No Grype, no OSV, no Syft.
	svc := NewService(
		&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: dir}, &fakeDetector{}, reg,
		[]ports.DetectionSource{ownadvisory.New(store)}, nil, fakeLic{}, nil,
	)

	res, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
	if err != nil {
		t.Fatalf("owned-only scan: %v", err)
	}

	// The owned SBOM producer must have cataloged lodash from the lockfile.
	var sawLodash bool
	for _, c := range res.SBOM.Components {
		if c.Name == "lodash" && c.Version == "4.17.0" {
			sawLodash = true
		}
	}
	if !sawLodash {
		t.Fatalf("owned SBOM producer did not catalog lodash@4.17.0 from the lockfile: %+v", res.SBOM.Components)
	}

	// The owned detection source must have matched it to the advisory — with no Syft or Grype in the pipeline.
	var found bool
	for _, v := range res.Vulnerabilities {
		if v.Component == "lodash" && v.ID == "CVE-2019-10744" {
			found = true
		}
	}
	if !found {
		t.Fatalf("owned detection did not flag lodash CVE-2019-10744 (owned engine not self-sufficient): %+v", res.Vulnerabilities)
	}

	// The readiness guard must NOT fire on a POPULATED owned corpus: the owned advisory store reports
	// non-empty freshness (memory.AdvisoryStore.AdvisoryFreshness), so the scan must not carry the
	// "no detection source had a usable vulnerability database" warning. (Completeness may still be
	// not-confident for the unrelated fake-workspace reason that this harness reports no lockfile marker.)
	for _, w := range res.SourceWarnings {
		if strings.Contains(w, "no detection source had a usable vulnerability database") {
			t.Errorf("readiness guard wrongly fired on a populated owned corpus: %q", w)
		}
	}
}
