package sca

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestBuildSPDXDeterministicAndValid(t *testing.T) {
	doc := &sbom.SBOM{
		TargetRef: "https://github.com/org/repo",
		Components: []sbom.Component{
			{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Licenses: []sbom.License{{SPDXID: "MIT"}}},
			{Name: "express", Version: "4.18.2", PURL: "pkg:npm/express@4.18.2"},
		},
	}
	created := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)

	a := buildSPDX(doc, doc.TargetRef, created)
	b := buildSPDX(doc, doc.TargetRef, created)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatal("buildSPDX must be deterministic")
	}
	if a.SPDXVersion != "SPDX-2.3" || a.DataLicense != "CC0-1.0" || a.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("spdx header wrong: %+v", a)
	}
	if len(a.Packages) != 2 {
		t.Fatalf("want 2 packages, got %d", len(a.Packages))
	}
	// sorted by name: express before lodash
	if a.Packages[0].Name != "express" || a.Packages[1].Name != "lodash" {
		t.Errorf("packages not sorted: %s, %s", a.Packages[0].Name, a.Packages[1].Name)
	}
	if a.Packages[1].LicenseDeclared != "MIT" {
		t.Errorf("lodash license = %q, want MIT", a.Packages[1].LicenseDeclared)
	}
	if a.Packages[0].LicenseDeclared != "NOASSERTION" {
		t.Errorf("express license = %q, want NOASSERTION", a.Packages[0].LicenseDeclared)
	}
	if len(a.Packages[1].ExternalRefs) != 1 || a.Packages[1].ExternalRefs[0].ReferenceLocator != "pkg:npm/lodash@4.17.21" {
		t.Errorf("purl externalRef missing: %+v", a.Packages[1].ExternalRefs)
	}
	if len(a.Relationships) != 2 || a.Relationships[0].RelationshipType != "DESCRIBES" {
		t.Errorf("relationships wrong: %+v", a.Relationships)
	}
}

func TestBuildSPDXEmitsSupplier(t *testing.T) {
	doc := &sbom.SBOM{
		TargetRef: "https://github.com/org/repo",
		Components: []sbom.Component{
			{Name: "commons-lang3", Version: "3.12.0", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.12.0", Supplier: "org.apache.commons"},
			{Name: "leftpad", Version: "1.0.0", PURL: "pkg:npm/leftpad@1.0.0"}, // no supplier
		},
	}
	a := buildSPDX(doc, doc.TargetRef, time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC))
	byName := map[string]spdxPackage{}
	for _, p := range a.Packages {
		byName[p.Name] = p
	}
	if got := byName["commons-lang3"].Supplier; got != "Organization: org.apache.commons" {
		t.Errorf("PackageSupplier = %q, want \"Organization: org.apache.commons\"", got)
	}
	if got := byName["leftpad"].Supplier; got != "" {
		t.Errorf("a component with no supplier must omit PackageSupplier, got %q", got)
	}
}

func TestBuildSPDXEmitsChecksums(t *testing.T) {
	// A hex SHA1 stays hex; an npm-style base64 SHA512 (Subresource Integrity) is converted to hex, since SPDX
	// requires a hex checksumValue.
	raw := make([]byte, 64) // a 64-byte digest = SHA512
	for i := range raw {
		raw[i] = byte(i * 3)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	wantHex := hex.EncodeToString(raw)
	sha1hex := "0123456789abcdef0123456789abcdef01234567"

	doc := &sbom.SBOM{
		TargetRef: "https://github.com/org/repo",
		Components: []sbom.Component{{
			Name: "a", Version: "1.0", PURL: "pkg:maven/g/a@1.0",
			SHA1:      sha1hex,
			Checksums: []sbom.Checksum{{Algorithm: "SHA512", Value: b64}},
		}},
	}
	pkg := buildSPDX(doc, doc.TargetRef, time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)).Packages[0]
	got := map[string]string{}
	for _, c := range pkg.Checksums {
		got[c.Algorithm] = c.ChecksumValue
	}
	if got["SHA1"] != sha1hex {
		t.Errorf("SHA1 checksum = %q, want the hex as-is %q", got["SHA1"], sha1hex)
	}
	if got["SHA512"] != wantHex {
		t.Errorf("SHA512 checksum = %q, want the base64 SRI converted to hex %q", got["SHA512"], wantHex)
	}
	// Deterministic + sorted by algorithm (SHA1 before SHA512).
	if len(pkg.Checksums) != 2 || pkg.Checksums[0].Algorithm != "SHA1" {
		t.Errorf("checksums must be sorted by algorithm, got %+v", pkg.Checksums)
	}
	// Robustness: garbage, wrong-length-for-algorithm, unknown algorithm, and an oversized value must all be
	// dropped – never emitted as a malformed or non-conformant SPDX checksum.
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	for _, bad := range []sbom.Checksum{
		{Algorithm: "SHA256", Value: "not-a-digest!!"},                              // not hex, not base64
		{Algorithm: "SHA512", Value: "deadbeef"},                                    // valid hex but wrong length for SHA512
		{Algorithm: "WEIRDHASH", Value: "0123456789abcdef0123456789abcdef01234567"}, // algorithm not in the allowlist
		{Algorithm: "SHA256", Value: string(long)},                                  // oversized value
	} {
		docBad := &sbom.SBOM{Components: []sbom.Component{{Name: "b", Version: "1.0", PURL: "pkg:maven/g/b@1.0", Checksums: []sbom.Checksum{bad}}}}
		if cks := buildSPDX(docBad, "t", time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)).Packages[0].Checksums; len(cks) != 0 {
			t.Errorf("bad checksum %+v must be dropped, got %+v", bad, cks)
		}
	}
	// A hyphen-stripped Syft algorithm ("SHA3256") still normalizes to the canonical SPDX name "SHA3-256".
	raw32 := make([]byte, 32)
	docSha3 := &sbom.SBOM{Components: []sbom.Component{{Name: "c", Version: "1.0", PURL: "pkg:maven/g/c@1.0", Checksums: []sbom.Checksum{{Algorithm: "SHA3256", Value: hex.EncodeToString(raw32)}}}}}
	if cks := buildSPDX(docSha3, "t", time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)).Packages[0].Checksums; len(cks) != 1 || cks[0].Algorithm != "SHA3-256" {
		t.Errorf("SHA3256 must canonicalize to the SPDX name SHA3-256, got %+v", cks)
	}
}

func TestScanTimePinned(t *testing.T) {
	r := ScanResult{VulnDBSnapshot: "osv.dev@2026-06-21T10:00:00Z"}
	if got := r.scanTime(); got.Format(time.RFC3339) != "2026-06-21T10:00:00Z" {
		t.Errorf("scanTime = %v, want pinned from snapshot", got)
	}
	// no snapshot -> stable zero time, never time.Now()
	if (ScanResult{}).scanTime() != time.Unix(0, 0).UTC() {
		t.Error("scanTime fallback must be the stable zero time")
	}
}

// The export gate delegates entirely to the shared domain digest gate, so an SPDX package emits the same
// canonical algorithm name + lowercase hex the scorer validated – and rejects what the scorer rejects.
func TestSPDXHexDigestDelegatesToDomainGate(t *testing.T) {
	name, hexVal, ok := spdxHexDigest("sha-256", strings.ToUpper(strings.Repeat("a", 64)))
	if !ok || name != "SHA256" || hexVal != strings.Repeat("a", 64) {
		t.Errorf("spdxHexDigest(sha-256, UPPER hex) = %q,%q,%v; want SHA256, lowercase hex, true", name, hexVal, ok)
	}
	if _, _, ok := spdxHexDigest("SHA256", "not-a-digest"); ok {
		t.Error("a malformed value must be dropped by the export gate")
	}
	if _, _, ok := spdxHexDigest("CRC32", strings.Repeat("a", 8)); ok {
		t.Error("an unrecognized algorithm must be dropped by the export gate")
	}
}
