package ownadvisory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestOVALEndToEnd wires the whole native OS-package path: parse a Ubuntu OVAL feed → key the store the way
// the matcher looks it up → derive the ecosystem from a Syft deb PURL → order versions with the owned dpkg
// comparator → emit a finding. No third-party scanner or service anywhere in the chain.
func TestOVALEndToEnd(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	advs, err := ParseUbuntuOVAL(data)
	if err != nil {
		t.Fatal(err)
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"Ubuntu:22.04|openssl": advs}}
	src := New(store)

	// A jammy openssl BELOW the fixed version is a real, matchable finding.
	vuln := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "3.0.2-0ubuntu1.9", PURL: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.9?arch=amd64&distro=ubuntu-22.04"},
	}}
	found, err := src.Scan(context.Background(), vuln)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 finding for a vulnerable jammy openssl, got %d", len(found))
	}
	f := found[0]
	if f.AdvisoryID != "CVE-2023-1000" || f.FixedVersion != "3.0.2-0ubuntu1.10" {
		t.Errorf("finding = %+v, want CVE-2023-1000 fixed 3.0.2-0ubuntu1.10", f)
	}
	if f.Severity != shared.SeverityMedium {
		t.Errorf("severity = %q, want medium (vendor rating mapped from OVAL)", f.Severity)
	}

	// The same package AT the fixed version is not a finding (backport-accurate, no false positive).
	patched := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "3.0.2-0ubuntu1.10", PURL: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=ubuntu-22.04"},
	}}
	found, err = src.Scan(context.Background(), patched)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("a patched openssl must not be flagged, got %+v", found)
	}

	// A different release (focal) must not match the jammy advisory (release isolation).
	focal := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "3.0.2-0ubuntu1.9", PURL: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.9?distro=ubuntu-20.04"},
	}}
	found, _ = src.Scan(context.Background(), focal)
	if len(found) != 0 {
		t.Errorf("a focal component must not match a jammy advisory, got %+v", found)
	}
}
