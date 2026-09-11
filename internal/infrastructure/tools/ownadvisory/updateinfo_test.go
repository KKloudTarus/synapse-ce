package ownadvisory

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// TestParseUpdateInfo parses a real (trimmed) Amazon Linux 2 updateinfo fixture into Amazon Linux:2
// advisories: a security ALAS fixing several CVEs expands to one advisory per CVE sharing the fixed packages,
// keyed by the collection's release.
func TestParseUpdateInfo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "updateinfo-amazonlinux2.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseUpdateInfo(data)
	if err != nil {
		t.Fatalf("ParseUpdateInfo: %v", err)
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range advs {
		byID[a.ID] = a
		for _, ap := range a.Affected {
			if ap.Ecosystem != "Amazon Linux:2" {
				t.Errorf("%s: ecosystem = %q, want Amazon Linux:2", a.ID, ap.Ecosystem)
			}
			if ap.Ranges[0].Type != "ECOSYSTEM" {
				t.Errorf("%s: range type = %q, want ECOSYSTEM", a.ID, ap.Ranges[0].Type)
			}
		}
	}
	// ALAS2-2018-939 fixes CVE-2017-5715 and CVE-2017-5754 in kernel; both advisories carry the kernel package.
	for _, cve := range []string{"CVE-2017-5715", "CVE-2017-5754"} {
		a, ok := byID[cve]
		if !ok {
			t.Fatalf("missing advisory for %s", cve)
		}
		found := false
		for _, ap := range a.Affected {
			if ap.Package == "kernel" && ap.FixedVersion == "0:4.9.76-38.79.amzn2" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected kernel fixed 0:4.9.76-38.79.amzn2, got %+v", cve, a.Affected)
		}
	}
}

// TestParseUpdateInfoMatchesViaDomainMatcher proves the Amazon Linux:2 key and the rpm comparator (with the
// .amzn2 dist tag and epoch) wire end to end.
func TestParseUpdateInfoMatchesViaDomainMatcher(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join("testdata", "updateinfo-amazonlinux2.xml"))
	advs, err := ParseUpdateInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	var kernel advisory.Advisory
	for _, a := range advs {
		if a.ID != "CVE-2017-5715" {
			continue
		}
		for _, ap := range a.Affected {
			if ap.Package == "kernel" {
				kernel = a
			}
		}
	}
	if kernel.ID == "" {
		t.Fatal("kernel advisory not parsed")
	}
	if ok, _ := kernel.Match("Amazon Linux:2", "kernel", "0:4.9.76-38.78.amzn2"); !ok {
		t.Error("an older kernel must match")
	}
	if ok, _ := kernel.Match("Amazon Linux:2", "kernel", "0:4.9.76-38.79.amzn2"); ok {
		t.Error("kernel at the fixed version must not match")
	}
	if ok, _ := kernel.Match("Amazon Linux:2023", "kernel", "0:4.9.76-38.78.amzn2"); ok {
		t.Error("a different Amazon release must not match")
	}
}

func TestAmazonRelease(t *testing.T) {
	cases := []struct{ short, name, want string }{
		{"amazon-linux-2", "Amazon Linux 2", "2"},
		{"amazon-linux-2023", "Amazon Linux 2023", "2023"},
		{"", "Amazon Linux 2", "2"},
		{"amazon-linux-2", "", "2"},
		{"rhel-9", "Red Hat Enterprise Linux 9", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		if got := amazonRelease(tc.short, tc.name); got != tc.want {
			t.Errorf("amazonRelease(%q, %q) = %q, want %q", tc.short, tc.name, got, tc.want)
		}
	}
}

func TestAmazonEcosystemKeyRoundTrip(t *testing.T) {
	for _, tc := range []struct{ purl, want string }{
		{"pkg:rpm/amzn/bash@5?arch=x86_64&distro=amzn-2", "Amazon Linux:2"},
		{"pkg:rpm/amzn/bash@5?distro=amzn-2023", "Amazon Linux:2023"},
	} {
		if got := osDistroEcosystem(tc.purl); got != tc.want {
			t.Errorf("osDistroEcosystem(%s) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

func TestRpmEVR(t *testing.T) {
	cases := []struct{ e, v, r, want string }{
		{"0", "4.9.76", "38.79.amzn2", "0:4.9.76-38.79.amzn2"},
		{"", "1.2", "3", "0:1.2-3"}, // epoch defaults to 0
		{"2", "1.0", "", "2:1.0"},   // no release
		{"0", "", "1.amzn2", ""},    // no version: not a boundary
	}
	for _, tc := range cases {
		if got := rpmEVR(tc.e, tc.v, tc.r); got != tc.want {
			t.Errorf("rpmEVR(%q,%q,%q) = %q, want %q", tc.e, tc.v, tc.r, got, tc.want)
		}
	}
}

// TestUpdateInfoSkipsNonSecurity proves a non-security update (bugfix/enhancement) yields no advisory.
func TestUpdateInfoSkipsNonSecurity(t *testing.T) {
	doc := []byte(`<updates><update type="bugfix"><id>ALAS2-B</id><title>Amazon Linux 2 bugfix</title>
	  <references><reference type="cve" id="CVE-2099-0001"/></references>
	  <pkglist><collection short="amazon-linux-2"><name>Amazon Linux 2</name>
	    <package name="foo" epoch="0" version="1.0" release="1.amzn2"/></collection></pkglist></update></updates>`)
	advs, err := ParseUpdateInfo(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Errorf("a bugfix update must yield no advisory, got %+v", advs)
	}
}

// TestParseUpdateInfoGzip proves the gzip feed path (Amazon ships updateinfo.xml.gz) parses identically.
func TestParseUpdateInfoGzip(t *testing.T) {
	plain, err := os.ReadFile(filepath.Join("testdata", "updateinfo-amazonlinux2.xml"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(plain); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	advs, err := ParseUpdateInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseUpdateInfo(gzip): %v", err)
	}
	if len(advs) == 0 || advs[0].Affected[0].Ecosystem != "Amazon Linux:2" {
		t.Errorf("gzip parse mismatch: %+v", advs)
	}
}

// TestUpdateInfoMaxWithinLineage proves that when a CVE is fixed for one package in two updates with
// same-lineage versions, the MAX (superseding) fixed version is kept, so a version between the two is still
// matched.
func TestUpdateInfoMaxWithinLineage(t *testing.T) {
	doc := []byte(`<updates>
	  <update type="security"><id>ALAS2-A</id><title>Amazon Linux 2</title>
	    <references><reference type="cve" id="CVE-2099-1000"/></references>
	    <pkglist><collection short="amazon-linux-2"><name>Amazon Linux 2</name>
	      <package name="kernel" epoch="0" version="4.14.33" release="59.34.amzn2"/></collection></pkglist></update>
	  <update type="security"><id>ALAS2-B</id><title>Amazon Linux 2</title>
	    <references><reference type="cve" id="CVE-2099-1000"/></references>
	    <pkglist><collection short="amazon-linux-2"><name>Amazon Linux 2</name>
	      <package name="kernel" epoch="0" version="4.14.42" release="61.37.amzn2"/></collection></pkglist></update>
	</updates>`)
	advs, err := ParseUpdateInfo(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || len(advs[0].Affected) != 1 {
		t.Fatalf("want one advisory with one kernel entry, got %+v", advs)
	}
	if advs[0].Affected[0].FixedVersion != "0:4.14.42-61.37.amzn2" {
		t.Errorf("want the max same-lineage fix 0:4.14.42-61.37.amzn2, got %q", advs[0].Affected[0].FixedVersion)
	}
	// a version BETWEEN the two fixes is still vulnerable and must match the max boundary
	if ok, _ := advs[0].Match("Amazon Linux:2", "kernel", "0:4.14.40-1.amzn2"); !ok {
		t.Error("a version below the max same-lineage fix must match")
	}
}

// TestUpdateInfoCrossLineageSkipped proves that when a CVE is fixed for one package across DIFFERENT lineages
// (e.g. the 4.9 and 4.14 kernels), the package is skipped rather than emitted with a lineage-blind range that
// would false-match a package fixed in the other lineage.
func TestUpdateInfoCrossLineageSkipped(t *testing.T) {
	doc := []byte(`<updates>
	  <update type="security"><id>ALAS2-A</id><title>Amazon Linux 2</title>
	    <references><reference type="cve" id="CVE-2099-2000"/></references>
	    <pkglist><collection short="amazon-linux-2"><name>Amazon Linux 2</name>
	      <package name="kernel" epoch="0" version="4.9.85" release="47.59.amzn2"/></collection></pkglist></update>
	  <update type="security"><id>ALAS2-B</id><title>Amazon Linux 2</title>
	    <references><reference type="cve" id="CVE-2099-2000"/></references>
	    <pkglist><collection short="amazon-linux-2"><name>Amazon Linux 2</name>
	      <package name="kernel" epoch="0" version="4.14.42" release="61.37.amzn2"/></collection></pkglist></update>
	</updates>`)
	advs, err := ParseUpdateInfo(doc)
	if err != nil {
		t.Fatal(err)
	}
	// the kernel is fixed across two lineages: it must be dropped, so no advisory falsely flags a fixed kernel
	for _, a := range advs {
		for _, ap := range a.Affected {
			if ap.Package == "kernel" {
				t.Errorf("a cross-lineage kernel must be skipped, got %s < %s", ap.Package, ap.FixedVersion)
			}
		}
	}
}

func TestAmazonReleaseAnchored(t *testing.T) {
	// A non-Amazon collection that merely CONTAINS "Amazon Linux 2" must not be keyed to Amazon Linux:2.
	if got := amazonRelease("", "EPEL for Amazon Linux 2"); got != "" {
		t.Errorf("amazonRelease(EPEL for Amazon Linux 2) = %q, want \"\"", got)
	}
	if got := amazonRelease("epel-amazon-linux-2", ""); got != "" {
		t.Errorf("a non-amazon-linux- short must not match, got %q", got)
	}
	// trailing text after the Amazon prefix must not be keyed (the release must be the whole remainder).
	if got := amazonRelease("amazon-linux-2-epel", ""); got != "" {
		t.Errorf("amazon-linux-2-epel must not key, got %q", got)
	}
	if got := amazonRelease("", "Amazon Linux 2 EPEL"); got != "" {
		t.Errorf("\"Amazon Linux 2 EPEL\" must not key, got %q", got)
	}
	// the real shapes still key correctly.
	if got := amazonRelease("amazon-linux-2023", ""); got != "2023" {
		t.Errorf("amazon-linux-2023 = %q, want 2023", got)
	}
}

func TestRpmLineage(t *testing.T) {
	cases := map[string]string{
		"0:4.14.42-61.37.amzn2": "4.14",
		"0:4.9.85-47.59.amzn2":  "4.9",
		"0:1.0.2k-16.amzn2":     "1.0",
		"2:5-1.amzn2":           "5",
	}
	for evr, want := range cases {
		if got := rpmLineage(evr); got != want {
			t.Errorf("rpmLineage(%q) = %q, want %q", evr, got, want)
		}
	}
}
