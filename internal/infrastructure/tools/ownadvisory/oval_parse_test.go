package ownadvisory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseUbuntuOVAL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseUbuntuOVAL(data)
	if err != nil {
		t.Fatalf("ParseUbuntuOVAL: %v", err)
	}
	// Only the fixed CVE yields an advisory; the deferred (no "less than" fix) one is skipped.
	if len(advs) != 1 {
		t.Fatalf("want 1 advisory (deferred CVE dropped), got %d: %+v", len(advs), advs)
	}
	a := advs[0]
	if a.ID != "CVE-2023-1000" {
		t.Errorf("id = %q, want CVE-2023-1000", a.ID)
	}
	if a.CVSSScore != 5.5 { // Medium mapped to a representative base score
		t.Errorf("CVSSScore = %v, want 5.5 (Medium)", a.CVSSScore)
	}
	if len(a.Affected) != 1 {
		t.Fatalf("want 1 affected package, got %d", len(a.Affected))
	}
	ap := a.Affected[0]
	if ap.Ecosystem != "Ubuntu:22.04" || ap.Package != "openssl" || ap.FixedVersion != "3.0.2-0ubuntu1.10" {
		t.Errorf("affected = %+v, want Ubuntu:22.04 openssl fixed 3.0.2-0ubuntu1.10", ap)
	}
	if ap.Ranges[0].Type != "ECOSYSTEM" {
		t.Error("OVAL affected range must be ECOSYSTEM type so the owned dpkg comparator orders it")
	}
}

func TestParseUbuntuOVALMatchesViaDomainMatcher(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml"))
	advs, err := ParseUbuntuOVAL(data)
	if err != nil {
		t.Fatal(err)
	}
	a := advs[0]
	// A lower dpkg version is affected; at/above the fixed version it is not – proves the owned dpkg
	// comparator wires up end to end through the "Ubuntu:22.04" ecosystem key.
	if ok, fixed := a.Match("Ubuntu:22.04", "openssl", "3.0.2-0ubuntu1.9"); !ok || fixed != "3.0.2-0ubuntu1.10" {
		t.Errorf("older openssl must match with fix 3.0.2-0ubuntu1.10, got ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := a.Match("Ubuntu:22.04", "openssl", "3.0.2-0ubuntu1.10"); ok {
		t.Error("openssl at the fixed version must not match")
	}
	if ok, _ := a.Match("Ubuntu:20.04", "openssl", "3.0.2-0ubuntu1.9"); ok {
		t.Error("a different release must not match (ecosystem key differs)")
	}
}

func TestParseUbuntuOVALBzip2(t *testing.T) {
	// The .bz2 fixture must parse identically to the plain XML (bzip2 magic-sniff path).
	data, err := os.ReadFile(filepath.Join("testdata", "oval-jammy.xml.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	advs, err := ParseUbuntuOVAL(data)
	if err != nil {
		t.Fatalf("ParseUbuntuOVAL(bz2): %v", err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2023-1000" || advs[0].Affected[0].Ecosystem != "Ubuntu:22.04" {
		t.Errorf("bz2 parse mismatch: %+v", advs)
	}
}

func TestParseUbuntuOVALUnknownReleaseSkipped(t *testing.T) {
	// A codename not in the release table is a per-file skip (error), not a mis-keyed advisory.
	x := `<oval_definitions><definitions>
	  <definition class="vulnerability" id="oval:com.ubuntu.bogus:def:1">
	    <metadata><reference source="CVE" ref_id="CVE-2023-9"/></metadata>
	    <criteria><criterion test_ref="oval:com.ubuntu.bogus:tst:1"/></criteria>
	  </definition></definitions></oval_definitions>`
	if _, err := ParseUbuntuOVAL([]byte(x)); err == nil {
		t.Error("an unknown ubuntu codename must return an error (per-file skip), not silently key it wrong")
	}
}

func TestUbuntuReleaseTable(t *testing.T) {
	cases := map[string]string{"focal": "20.04", "jammy": "22.04", "noble": "24.04", "bionic": "18.04", "unknown": ""}
	for codename, want := range cases {
		if got := ubuntuRelease(codename); got != want {
			t.Errorf("ubuntuRelease(%q) = %q, want %q", codename, got, want)
		}
	}
}

func TestUbuntuSeverityScore(t *testing.T) {
	cases := map[string]float64{"Critical": 9.5, "High": 8.0, "Medium": 5.5, "Low": 3.0, "Negligible": 1.0, "untriaged": 0}
	for sev, want := range cases {
		if got := ubuntuSeverityScore(sev); got != want {
			t.Errorf("ubuntuSeverityScore(%q) = %v, want %v", sev, got, want)
		}
	}
}

// TestOVALEcosystemKeyRoundTrip locks the feed side (ubuntuRelease) to the matcher side (osDistroEcosystem):
// the key ParseUbuntuOVAL writes for a codename MUST equal the key a Syft ubuntu PURL for that release
// derives, or every finding for that release silently vanishes. A point-release qualifier must land on the
// same major.minor key.
func TestOVALEcosystemKeyRoundTrip(t *testing.T) {
	for _, codename := range []string{"bionic", "focal", "jammy", "noble"} {
		rel := ubuntuRelease(codename)
		if rel == "" {
			t.Fatalf("release table missing %q", codename)
		}
		want := "Ubuntu:" + rel // the exact key ParseUbuntuOVAL stores
		if got := osDistroEcosystem("pkg:deb/ubuntu/bash@5?distro=ubuntu-" + rel); got != want {
			t.Errorf("release %s: matcher key %q != feed key %q", rel, got, want)
		}
		// a point-release qualifier must normalize to the same key
		if got := osDistroEcosystem("pkg:deb/ubuntu/bash@5?distro=ubuntu-" + rel + ".2"); got != want {
			t.Errorf("release %s point-release: matcher key %q != feed key %q", rel, got, want)
		}
	}
}

func TestParseUbuntuOVALMalformedXML(t *testing.T) {
	if _, err := ParseUbuntuOVAL([]byte("<oval_definitions><definitions><definition")); err == nil {
		t.Error("truncated XML must return an error so the walk skips + counts the file")
	}
}
