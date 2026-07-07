package sbom

import "testing"

func TestDedupeComponentsUnionsLicenses(t *testing.T) {
	// The reported bug: Syft emits the same package twice — one entry with the resolved license,
	// one with none. After dedup there must be a SINGLE component carrying the license (no phantom
	// license-less twin that reads as UNKNOWN downstream).
	in := []Component{
		{Name: "commons-lang3", Version: "3.14.0", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
			Licenses: []License{{SPDXID: "Apache-2.0"}}, LicenseSource: "local-file", Location: "app.jar"},
		{Name: "commons-lang3", Version: "3.14.0", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
			Licenses: nil, UnknownReason: ReasonMetadataMissing},
	}
	out := DedupeComponents(in)
	if len(out) != 1 {
		t.Fatalf("want 1 merged component, got %d: %+v", len(out), out)
	}
	c := out[0]
	if len(c.Licenses) != 1 || c.Licenses[0].SPDXID != "Apache-2.0" {
		t.Errorf("merged licenses = %+v, want [Apache-2.0]", c.Licenses)
	}
	if c.UnknownReason != "" {
		t.Errorf("UnknownReason must be cleared once a license is present, got %q", c.UnknownReason)
	}
	if c.LicenseSource != "local-file" || c.Location != "app.jar" {
		t.Errorf("non-empty fields from the first entry must survive: %+v", c)
	}
}

func TestDedupeComponentsPreservesSupplierAndChecksums(t *testing.T) {
	// A Syft phantom-twin split: the licensed entry carries no integrity/supplier, the other twin carries
	// the only checksum + supplier. The merge must keep ALL of it — dropping the checksum would under-count
	// the SBOM quality score.
	in := []Component{
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Licenses: []License{{SPDXID: "MIT"}}},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21",
			Supplier: "acme", SupplierSource: SupplierDeclared, SHA1: "abc",
			Checksums: []Checksum{{Algorithm: "SHA512", Value: "zzz"}}},
	}
	out := DedupeComponents(in)
	if len(out) != 1 {
		t.Fatalf("want 1 merged component, got %d", len(out))
	}
	c := out[0]
	if c.Supplier != "acme" || c.SupplierSource != SupplierDeclared {
		t.Errorf("supplier + source must survive the merge, got %q/%q", c.Supplier, c.SupplierSource)
	}
	if c.SHA1 != "abc" || len(c.Checksums) != 1 || c.Checksums[0].Value != "zzz" {
		t.Errorf("integrity digests must survive the merge, got SHA1=%q Checksums=%+v", c.SHA1, c.Checksums)
	}
	if len(c.Licenses) != 1 { // and the first entry's license is still there
		t.Errorf("license from the first entry must survive, got %+v", c.Licenses)
	}
}

func TestDedupeComponentsFillsEmptyTwin(t *testing.T) {
	// Order-independent: the license-less entry first, the licensed one second.
	in := []Component{
		{Name: "gson", Version: "2.10.1", PURL: "pkg:maven/com.google.code.gson/gson@2.10.1"},
		{Name: "gson", Version: "2.10.1", PURL: "pkg:maven/com.google.code.gson/gson@2.10.1",
			Licenses: []License{{SPDXID: "Apache-2.0"}}, LayerID: "sha256:l", FirstParty: true},
	}
	out := DedupeComponents(in)
	if len(out) != 1 || len(out[0].Licenses) != 1 {
		t.Fatalf("want 1 component with 1 license, got %+v", out)
	}
	if out[0].LayerID != "sha256:l" {
		t.Errorf("empty field must be filled from the twin: LayerID=%q", out[0].LayerID)
	}
	if !out[0].FirstParty {
		t.Errorf("FirstParty must be a true OR across instances")
	}
}

func TestDedupeComponentsKeepsDistinct(t *testing.T) {
	// Different PURL = different package (don't merge). Different version = don't merge.
	in := []Component{
		{Name: "x", Version: "1", PURL: "pkg:npm/x@1", Licenses: []License{{SPDXID: "MIT"}}},
		{Name: "x", Version: "1", PURL: "pkg:pypi/x@1"}, // same name+version, DIFFERENT ecosystem
		{Name: "x", Version: "2", PURL: "pkg:npm/x@2"},
	}
	out := DedupeComponents(in)
	if len(out) != 3 {
		t.Fatalf("distinct PURLs/versions must stay separate, got %d: %+v", len(out), out)
	}
}

func TestDedupeComponentsMultiLicenseUnion(t *testing.T) {
	// A dual-license package whose two licenses arrive on separate evidence entries → unioned, deduped.
	in := []Component{
		{Name: "lombok", Version: "1.18.30", PURL: "pkg:maven/org.projectlombok/lombok@1.18.30", Licenses: []License{{SPDXID: "BSD-3-Clause"}}},
		{Name: "lombok", Version: "1.18.30", PURL: "pkg:maven/org.projectlombok/lombok@1.18.30", Licenses: []License{{SPDXID: "MIT"}, {SPDXID: "BSD-3-Clause"}}},
	}
	out := DedupeComponents(in)
	if len(out) != 1 || len(out[0].Licenses) != 2 {
		t.Fatalf("want 1 component with 2 unioned licenses, got %+v", out)
	}
}

func TestDedupeComponentsAnonymousNotMerged(t *testing.T) {
	// Entries with no identity (no PURL, missing name or version) must never be collapsed together.
	in := []Component{
		{Name: "", Version: "", PURL: ""},
		{Name: "", Version: "", PURL: ""},
		{Name: "only-name", Version: "", PURL: ""},
	}
	out := DedupeComponents(in)
	if len(out) != 3 {
		t.Fatalf("unidentifiable components must be kept as-is, got %d", len(out))
	}
}
