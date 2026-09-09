package ownadvisory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// cpeMemStore serves both the package index (ByPackage) and the NVD/CSAF CPE index (ByCPE), like the
// Postgres advisory repository, so the source's CPE path is exercised.
type cpeMemStore struct {
	byPkg map[string][]advisory.Advisory
	byCPE map[string][]advisory.Advisory
}

func (m cpeMemStore) ByPackage(_ context.Context, eco, name string) ([]advisory.Advisory, error) {
	return m.byPkg[eco+"|"+name], nil
}

func (m cpeMemStore) ByCPE(_ context.Context, part, vendor, product string) ([]advisory.Advisory, error) {
	return m.byCPE[part+"|"+vendor+"|"+product], nil
}

func TestScanMatchesNVDOnlyCVEViaCPE(t *testing.T) {
	// An NVD-only advisory with a CPE applicability statement and NO package (OSV) block.
	advCPE := advisory.Advisory{
		ID: "CVE-2022-0001", Summary: "openssl infinite loop", CVSSScore: 7.5,
		CPEs: []advisory.CPEMatch{{Criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "3.0.7"}},
	}
	store := cpeMemStore{
		byPkg: map[string][]advisory.Advisory{},
		byCPE: map[string][]advisory.Advisory{"a|openssl|openssl": {advCPE}},
	}
	// A component with a CPE whose PURL ecosystem the OSV feeds do not key ("generic"), so ONLY the CPE
	// path can find it - exactly the NVD-only recall gap.
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "3.0.1", PURL: "pkg:generic/openssl@3.0.1", CPE: "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"}, // affected (< 3.0.7)
		{Name: "openssl", Version: "3.1.0", PURL: "pkg:generic/openssl@3.1.0", CPE: "cpe:2.3:a:openssl:openssl:3.1.0:*:*:*:*:*:*:*"}, // patched (>= 3.0.7)
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("want 1 CPE finding (only the 3.0.1 component), got %d: %+v", len(raws), raws)
	}
	if raws[0].AdvisoryID != "CVE-2022-0001" || raws[0].Component != "openssl" || raws[0].Version != "3.0.1" {
		t.Fatalf("CPE finding wrong: %+v", raws[0])
	}
}

func TestScanCPEWithdrawnIsSkipped(t *testing.T) {
	advCPE := advisory.Advisory{
		ID: "CVE-2022-0002", Withdrawn: true,
		CPEs: []advisory.CPEMatch{{Criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "3.0.7"}},
	}
	store := cpeMemStore{byCPE: map[string][]advisory.Advisory{"a|openssl|openssl": {advCPE}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "3.0.1", PURL: "pkg:generic/openssl@3.0.1", CPE: "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 0 {
		t.Fatalf("a withdrawn advisory must not match via CPE, got %+v", raws)
	}
}

func TestScanDedupsPackageAndCPEHit(t *testing.T) {
	// One advisory reachable by BOTH the package index and the CPE index for the same component must
	// produce exactly one finding, not two.
	adv := advisory.Advisory{
		ID: "CVE-2021-0003", CVSSScore: 9.8,
		Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "foo", FixedVersion: "2.0.0",
			Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}}}},
		CPEs: []advisory.CPEMatch{{Criteria: "cpe:2.3:a:foo:foo:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "2.0.0"}},
	}
	store := cpeMemStore{
		byPkg: map[string][]advisory.Advisory{"npm|foo": {adv}},
		byCPE: map[string][]advisory.Advisory{"a|foo|foo": {adv}},
	}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "foo", Version: "1.5.0", PURL: "pkg:npm/foo@1.5.0", CPE: "cpe:2.3:a:foo:foo:1.5.0:*:*:*:*:*:*:*"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("package + CPE hit on the same advisory/component must dedup to 1 finding, got %d: %+v", len(raws), raws)
	}
}

func TestScanCPEHonorsNonVulnerableExclusion(t *testing.T) {
	// Vulnerable range < 3.0.7, but an explicit non-vulnerable statement for exactly 3.0.1 excludes it.
	adv := advisory.Advisory{
		ID: "CVE-2022-0004", CVSSScore: 7.5,
		CPEs: []advisory.CPEMatch{
			{Criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "3.0.7"},
			{Criteria: "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*", Vulnerable: false},
		},
	}
	store := cpeMemStore{byCPE: map[string][]advisory.Advisory{"a|openssl|openssl": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "3.0.1", PURL: "pkg:generic/openssl@3.0.1", CPE: "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"}, // excluded -> no finding
		{Name: "openssl", Version: "3.0.2", PURL: "pkg:generic/openssl@3.0.2", CPE: "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"}, // in range, not excluded -> finding
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 || raws[0].Version != "3.0.2" {
		t.Fatalf("exclusion must drop 3.0.1 and keep 3.0.2, got %+v", raws)
	}
}
